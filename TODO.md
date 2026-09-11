# rdns — TODO / Next Steps

Working notes for picking this up cold: what is open, what state the tree is in,
how to run it, and how to check a change on the platform this machine does not
compile.

**The three files, and which question each answers.** This one says *what is
open*. `CLAUDE.md` says *which mistakes this codebase has already made* and the
rules that follow from them — read it before planning; its first rule is why a
green suite here has twice not meant what it looked like. `docs/spec/` says
*what the code actually does*, in seven files derived by reading it rather than
by reading intent, with every known RFC deviation and gap collected in one
table.

**A fourth file as of 2026-09-05: `docs/CLOSED_WORK.md`.** Everything finished
lives there — ~~twenty-eight numbered sections covering thirty-one numbers~~, and
the log of what landed, verbatim, strike-throughs and wrong claims included.
`grep -c '^### [0-9]' docs/CLOSED_WORK.md` is the count, rather than a number
written here: the struck one was already wrong when it was written on 2026-09-05
(there were twenty-nine sections, not twenty-eight), and what the "thirty-one
numbers" counted is not recoverable — #5, #8 and #9 are closed with no section
of their own, and #21 has a section in *this* file. That is the ninth time a
count in a preamble here has gone stale, and the first fixed by deleting the
count.
This page had reached 7,989 lines of which about six thousand described work
that was already done, so the queue was three screens and the archive was
seventy. Closed items are one row each in
"Closed work" below, pointing there and at the commit.

**Nothing here describes a particular machine.** Paths, the Linux image and its
invocation, the git remote, what is installed and why port 53 misbehaves live in
`CLAUDE.local.md`, which is untracked and imported by `CLAUDE.md`. What stayed is
every *measurement* and every caveat needed to trust one; those say
"the development machine" and the local file says which.

---

## What is open

~~**One inventory and one numbered section**, as of 2026-09-08.~~ ~~**One
inventory**, later the same day: #37 closed on the day it was filed.~~
**One inventory and one numbered section again, 2026-09-09**: **#38**, from a
structural review asked for that day. Its three fixes are committed and ~~five
sub-items are open~~ — ~~**four and a half, later the same day**: 38d's `rdnsr`
half is done and its `rdnsd` half is not~~ ~~**three and a half on 2026-09-10**,
38b having gone too~~ ~~**two and a half the same day**, 38e having gone as well —
its cross-crate half decided against rather than done, which the row explains~~
~~**one and a half**, 38c having gone too: **38a**, and 38d's `rdnsd` half~~
~~**half of one**, 38a having gone as well: 38d's `rdnsd` half is all that is left,
and it is the one that needs an argument with #20 rather than a session.~~
~~**None of #38, and #39 and #40 on 2026-09-10**~~ — 38d closed the same day: the argument was taken, taking
it filed the API shape it depends on (#39), and a pass over the joints between
the internal APIs filed #40. None of #38 was a defect; #39 carries one, #40
none. **One inventory and one numbered section again, 2026-09-11**: #39 closed
with 39d, so what is open is **#40**'s ~~40d and 40f~~ **40f**, 40d having gone
the same day, and #21.

- ~~**#37** — where a module folder pays, and where it is motion. Four items, of
  which one (37a, five name helpers #35 and #36 left behind) is the only one
  with teeth; the rest are preventative. Filed with the measurement #33's rule
  demands, which for a split is *visibility* and not line count. **37a is done
  (2026-09-08)** and was a defect, not a cleanup — see the section. 37b-37d
  remain, and remain preventative.~~ **All four done 2026-09-08, the day it was
  filed**; the section is in `docs/CLOSED_WORK.md`. 37a was a defect, 37b, 37c
  and 37d each corrected the count in their own row, and 37d dropped the fifth
  module its row asked for because it would have widened rather than sealed.
- **#21** — the four deliberate RFC deviations and the not-implemented list.
  **Not a queue.** It exists so the next person to notice one finds the decision
  instead of re-deriving it. If one is ever taken up it gets its own number.

**#33 closed on 2026-09-06**, its last two items a day after the rest; the
section is in `docs/CLOSED_WORK.md` under its own number, where the five
candidates it *dropped* are the half worth reading.

**#35, SVCB and HTTPS (RFC 9460), filed and closed 2026-09-07.** The largest
remaining entry on #21's not-implemented list, and the one #34's closing note
named next. Stored and served as opaque RDATA before; readable and writable in a
zone file now, with RFC 9460 Appendix D's test vectors as a test. It also made
this tree implement RFC 1035 §5.1's escapes for the first time, which turned up
a latent defect in name parsing that had nothing to do with SVCB. §4.1/§4.2's
additional-section prefetching is deliberately not done and the section says why.

**#34, DNAME (RFC 6672), filed and closed 2026-09-06.** Taken because #21's
not-implemented list named it the only entry there that made this server answer
*wrong* rather than incomplete. Five commits: the record type, the zone, the
server algorithm, the resolver, then signing and UPDATE. RFC 6672's Table 1 is a
test verbatim, and dnspython validates the DNAME's RRSIG against a running
`rdnsd`. The section is in `docs/CLOSED_WORK.md`.

**Everything else numbered is closed, withdrawn, or answered no**, and the table
under "Closed work" says which, when, and where the reasoning is.

~~**Outside the numbered sections, one thing is genuinely pending: nothing here
has ever been pushed.**~~ **Wrong as of 2026-09-08**, and the tenth time a
sentence on this page outlived the thing it described: `origin/main` and `HEAD`
are both `c2f5900` in this clone, so the count below is **0** and the work has
in fact gone up. Kept rather than rewritten because the count is the lesson —
`git rev-list --count origin/main..HEAD` says how far ahead, and a sentence
saying it for you goes stale. What is still true is that the CI jobs may not
have been *read*. It was 49 on 2026-09-05, and five CI jobs had never been read:
msrv, deny, the container image, the `dhat-heap` feature build, and clippy on
Linux. That is the operator's call, not a session's: see "Do not push" below.
**Pushed on 2026-09-09**, so `origin/main` and `HEAD` are both `acd229e` and the
count is 0 again. The eight commits it carried are all of #37. The *reading*
half stays open and stays the owner's: there is no `gh` on this machine, so a
session cannot open a run from here at all.

**A count in a preamble goes stale whenever the list under it changes**, which
happened to this page's summary paragraphs at least ~~eight~~ ~~nine~~ **ten**
times
between 2026-07-30 and 2026-09-06 — the ninth is the `docs/CLOSED_WORK.md`
section count above, found wrong on 2026-09-06 and already wrong on the day it
was written — each corrected in place rather than reworded. The record is kept
under "How the queue kept going stale" in `docs/CLOSED_WORK.md`, because the
shape is the lesson. What this rewrite did about it is not a better paragraph
but a shorter list: two items cannot drift from a summary of two items. ~~It is
one item as of 2026-09-06~~ — ~~**two as of 2026-09-08**, #37 having been filed,~~
**one again the same day**, #37 having closed,
and the summary above was corrected in the same commit both times rather than a
later one, which is the only way this has ever stayed true. Not a tenth
staleness: a count updated with the list it counts is the behaviour, not the
failure. Whether it holds is a question for the next reader who finds this page
wrong.

**The five claims on this page that were wrong**, kept because the reasoning is
the useful part (`CLAUDE.md` §11 — correct in place, never quietly):

- *"CI runs all of this now"* (2026-07-30), while `git remote -v` was empty. The
  cost was `rdnsd` not compiling on Unix for a month.
- *"`enumerate_zone_files` already returns `Ok(empty)` for an empty directory"*,
  which went into a commit message, a doc comment and this file without anyone
  reading the twenty lines that would have settled it. It returned `Err`, and a
  secondary pointed at an empty directory then refused to start.
- *"twenty-eight numbered sections covering thirty-one numbers"* — written the
  day `docs/CLOSED_WORK.md` was split out and wrong that day: there were
  twenty-nine sections. Replaced above with the `grep` that answers it, which is
  the same move as `git rev-list --count` two paragraphs up.
- *"nothing here has ever been pushed"* (2026-09-05 onward), while
  `origin/main` had caught up with `HEAD`. Found on 2026-09-08 by running the
  command the same paragraph names. A sentence that restates a command's output
  is a cache with no invalidation.
- *"the profiler is global, so every test now holds the mutex for its whole
  body"* — true and insufficient. A mutex in a test file cannot serialize
  libtest's own bookkeeping on its other threads, which is why
  `rdns/tests/allocations.rs` is one `#[test]` today.

---

## Current state (last updated 2026-09-06)

**Workspace** — ~~five~~ **seven** members, all on branch `main` (it was
`master` until 2026-08-01; the rename is why older commit messages say the other
one). Two are new as of 2026-09-05 and are #31's answer:

| crate            | what it is                                                   |
|------------------|--------------------------------------------------------------|
| `rdns-core`      | the wire format and the names in it: messages, records, compression, presentation names, admission, the control protocol. No `tokio`, no crypto |
| `rdns`           | DNS above the wire: zones, DNSSEC, transfers, the resolver, the operational furniture. Re-exports all of `rdns-core` |
| `rdns-transport` | the socket layer both daemons run: admission, framing, accept loops, the shutdown epilogue. May use `anyhow`, which is why it is not a module of `rdns` (`CLAUDE.md` §3) |
| `rdnsc`          | command-line query client. Synchronous, and links `rdns-core` alone |
| `rdnsctl`        | control client for a running `rdnsd`: `status`, `reload`, `dump` (Unix only) |
| `rdnsd`          | authoritative server — serves zone files over UDP and TCP in one process |
| `rdnsr`          | recursive resolver with a caching layer; forwards on `--upstream` |

**There is a remote, and CI has run at last (2026-08-01).**
`.github/workflows/ci.yml` finally has somewhere to execute: seven job-runs per
push — `test` on Linux *and* Windows, plus lint, msrv, deny, image and features.
`concurrency` with `cancel-in-progress` is set, so a second push abandons the
first run rather than running both.

**Do not push from a session.** Commit locally and stop. Which remote, and why a
push costs something, are in `CLAUDE.local.md`.

~~**The tree is a long way ahead of `origin/main` and CI has seen none of it** —
`git rev-list --count origin/main..HEAD` is the number, and it was 49 on
2026-09-05.~~ **0 as of 2026-09-09**, pushed at `acd229e`. Five of the seven
jobs have still never been read at all; see "Where to pick up next".

This sentence and the two in the preamble and under "Where to pick up next" are
the same fact written three times, which is #30's lesson arriving on this page
rather than in the code: a status held in three places disagrees eventually, and
all three did. The command beside each is the only part that cannot go stale.

**The first CI run failed, and the failure was the test's fault rather than the
code's.** One job failed and one warning appeared across several; both are fixed
locally and unpushed, and nothing was wrong with the code CI was checking. The
Windows `build and test` job failed
`a_reload_does_not_hold_the_write_lock_across_its_diffs` at 71% of samples locked
out, where the development machine measures 0.3% for the same code. `tokio::sync::RwLock` is
fair, so `try_read` fails while a writer is merely *queued*: the metric was
measuring scheduler wake latency, and its denominator was the sampler's own spin
rate, which is not a clock. The test measures a window of *time* against a
baseline diff it times on the machine it is running on now. Fixed and verified
both ways under starvation (`8758476`).

The warning was `actions/checkout@v4` targeting Node 20, bumped to `@v5` in the
same commit. It showed up in several jobs' logs, one of which is named `licences
and advisories` — **`cargo deny` itself passed.** Reading a job name as a
description of its complaint is a mistake worth not repeating: the names here say
what a job checks.

**The reason CI mattered is on this page in the form of a mistake.** A
2026-07-30 entry here claimed *"CI runs all of this now"* when `git remote -v`
was empty; the claim was wrong for a month and the cost was not hypothetical —
`rdnsd` **did not compile on Unix at all** from the day SIGHUP reloading was
written until 2026-08-01, because the call needed a `StreamExt` nothing imported
and the module is `#[cfg(unix)]` in a workspace developed on Windows. The
reasoning that produced the wrong claim is kept rather than deleted, because it
is the most useful thing on this page: the file asserting a property is not the
thing that upholds it (`CLAUDE.md` §4).

**The history was rewritten on 2026-08-01, so every commit hash changed.** Each
message carried a `Claude-Session:` trailer holding a session URL — 118 of the
150 commits — and they were stripped with `git filter-branch --msg-filter`. Only
the messages changed: the tree at the old head and the tree at the new one are
byte-identical. Any hash written down *outside* this repository is now dangling;
inside it, the commit references in "Done so far" (now
`docs/CLOSED_WORK.md`) and the entry in
`.git-blame-ignore-revs` were remapped by matching subjects, and every one
resolves. The blame file is the one that would have failed loudly rather than
quietly — `git blame` refuses a revision it cannot resolve.

**The history was rewritten again on 2026-08-30, into a series of 54
patches.** 218 commits became 54. The machine this is developed on was
removed from every blob and every message, not only from the tracked files at
the tip; the OpenTelemetry exporter was removed from the code and from every
lock file it appeared in; nine add-then-delete planning documents and a
checked-in `dnssec.rs.backup` were dropped; and what remained was squashed to
one patch per logical change, each with a message written to the convention in
`CLAUDE.md` §11. The tree at the old head and the tree at the new one are
byte-identical, and every patch in the series compiles on its own.

Three consequences worth knowing. A hash written down outside this repository
is dangling for the second time. `git log -S` for the OpenTelemetry exporter
finds nothing, so `CLAUDE.md` §14 keeps the finding while the diff that
produced its numbers is gone: `git show` on the commit that deleted it reports
`Cargo.lock` going from 109 packages to 104, where §14 says 187 to 104 — the
83 crates the exporter dragged in were scrubbed from the history one commit at
a time rather than at that commit. And the commit references in this file, in
`docs/` and in `.git-blame-ignore-revs` were remapped again by matching
subjects; several now point at one patch, because the commits they named were
squashed together.

**Green as of the last commit**, on both platforms and checked on both —
re-measured 2026-09-06 on the same tree, minutes apart:

| | Windows | Linux |
|---|---|---|
| `rdns-core` | 160 | 160 |
| `rdns` lib | 582 | **585** |
| allocations | 1 | 1 |
| no_input_panics | 1 | 1 |
| `rdns-transport` | 3 | 3 |
| `rdnsd` | 109 | **122** |
| `rdnsr` | 10 | 10 |
| **total** | **866** | **882** |

~~854 / 870~~ was 2026-09-05's pair, and it was already a commit behind when it
was written: the +3 in `rdns-core` and most of the +8 in the library are 33b's
`Qtype` work and the transfer MAC chain, not this day's. The gap is unchanged at
16 because every one of those is platform-independent — #33g moved fixtures
without touching a test body, and #33h added the single `rdns-transport` test.

~~805 / 821~~ was 2026-08-05's pair, before `rdns-core` and `rdns-transport`
existed; the library's 691/694 is now 157 + 574 / 157 + 577 across the split.
The gap is still **16** and still exactly the sixteen `#[cfg(unix)]` tests
below, which is the check §1 of `CLAUDE.md` says a differing count is the tell
for.

~~**The Windows column is current and the Linux one is not.** Linux was last
measured before #13 landed; the gap between the columns is the sixteen
`#[cfg(unix)]` tests below plus whatever has been added since, and it is no
longer safe to read it as only the former. Re-run the recipe under "Running
the Linux half by hand" before quoting the right-hand column.~~

**Both columns re-measured 2026-08-05, on the same tree, minutes apart** — the
numbers above replace 2026-08-04's pair (684/687, 101/114, 793/809), which
replaced a staler one (655/633, 94/106, 754/744). The gap is
**16**, and it is exactly the sixteen `#[cfg(unix)]` tests described below: +3 in
the library (the mode checks) and +13 in `rdnsd` (the control socket). That the
difference is now *only* the cfg-gated tests is the check worth making, and it is
the one §1 of `CLAUDE.md` says a differing count is the tell for — the previous
pair had Windows *ahead*, which cannot be right and was the stale column showing.

The Linux run was `cargo test --workspace` **against the Windows-mounted tree**
rather than a copy inside the image, against the warning under "Running the Linux
half by hand" — which turns out not to apply to the three tests it is about; see
the note there. `cargo clippy --workspace --all-targets` is clean there too,
which is the half Windows cannot check at all.

**Two of those single tests are worth more than their count suggests.**
`allocations` reports **forty-two** measurements, **thirty-two** of them exact
(`n..=n`) — ~~twenty-nine and twenty~~ before #27 and #29 landed, twenty-two and
fourteen before the shapes added on 2026-08-31, nineteen and thirteen before
that, and the claim of
"fourteen exact" at the start was never counted and was wrong both ways; ten
are deliberate ranges and one
(`verify a DNSKEY RRset with two candidate signatures`) is `0..=u64::MAX`, a
figure printed on purpose and asserted on purpose not at all, because §10 found
it is a time problem and not a count problem. `no_input_panics` runs 1,506
mutated messages through the pre-authentication path — 1.4 million of them when
soaked. A test count is a poor summary of a suite and this is where it shows.

**Sixteen tests exist on Linux only**, and they are the ones a green Windows run
says nothing about: two on the secret-file mode check and one on the private-key
loader (there are no mode bits on Windows), and thirteen for the control socket,
which needs a Unix domain socket and so is `#[cfg(unix)]` in its entirety.

**The allocation counts are the same on both platforms**, which is worth a line
because it is not obvious: what is counted is calls into the global allocator, so
it does not depend on whether glibc's malloc or Windows' heap is underneath.
Every exact assertion in `rdns/tests/allocations.rs` (0, 1, 2, 2, 3, 3 and 4)
reads the same on Linux.

The counting moved out of `dhat` on 2026-08-30, having been read from its
`total_blocks` since the file was written: those counters are global, so another
thread allocating inside a window of a few microseconds lands in the total. CI
read 10 for the EDNS parse that reads 6 on Windows (rustc 1.95 and 1.98) and
Linux (1.97.1, and stable 1.98 in a fresh clone run in CI's step order),
and the same commit passed on a re-run. The file counts its own thread's calls
now; what holds that is a probe of a hundred parses beside a thread allocating in
a loop — 300, against 687 for the version that asked dhat.

`cargo clippy --workspace --all-targets` and `cargo fmt --all --check` are clean
**on Windows, and clippy is clean on Linux too** — both re-run 2026-09-05.
~~the image used for the Linux runs has no clippy package,
so that half is checked by CI now and was checked nowhere before.~~

**Corrected 2026-08-04: it has clippy, and always may have.** The workspace is
**clean** under `cargo clippy --workspace --all-targets` there — a stronger
statement than the Windows run can make, because Linux is the only side that
compiles `rdnsd/src/control.rs` and the rest of the `#[cfg(unix)]` half at all.
The claim went into this file, into "Where to pick up next" and into one more
place below without anyone typing the command; `CLAUDE.md` §1's own instruction
has said to run clippy on the other side the whole time, so the two documents
disagreed and neither was checked. §4, again, and the same shape as #26j: a
statement about a *tool*, written from memory of one failure rather than from
running it. The version and the paths are in `CLAUDE.local.md`.

**Errors are typed in the library and `anyhow` in the binaries.** The convention
used to run the other way round. `rdns::error` holds seven types (`WireError`,
`RequestError`, `ZoneError`, `DnssecError`, `TransferError`, `ResolveError`,
`ConfigError`) whose variants are the decisions a caller actually makes:
truncated is FORMERR and unsupported is NOTIMP, a bogus signature is SERVFAIL and
an unknown algorithm is insecure, a transfer timeout is retried and a malformed
one is not — and a packet that decoded perfectly but has QR=1 gets no reply at
all, which is why that one is not a `WireError`. See `CLAUDE.md` §3.

**Green did not mean conformant, and the fix for that is `CLAUDE.md`.** The suite
passed at 590 tests while `rdnsd` could not serve a CNAME, a delegation or a
two-label wildcard, because the tests were written from the same understanding as
the code — two of them asserted the wrong behaviour and cited an RFC section that
says nothing about the subject. That is now the first rule in `CLAUDE.md`.

**What the answer path costs now**, because it took three changes to find out and
the numbers are the input to any future attempt. Measured on `rdnsd` itself with
`--features dhat-heap` on 2026-08-31 — 2 000 queries against a 716-block startup
baseline, linear to three decimals, and every program point dhat attributes is a
site `rdns/tests/allocations.rs` now measures:

~~| | plain | EDNS0+DO+cookie |~~
~~| lower-case QNAME | 13.0 | 16.0 |~~
~~| case randomized (DNS-0x20) | 18.0 | 21.0 |~~
~~| NXDOMAIN, unsigned zone | 19.0 | 22.0 |~~

**Superseded by #27, which closed on 2026-09-05 and is what those numbers were
filed to justify.** The table above is the *before* picture and is kept because
#27's whole argument is the difference. Measured the same way after 27f:

| shape | allocations per query |
|---|---|
| plain A, lower-case QNAME | **2.003** |
| EDNS0 + DO + DNS-0x20 | **2.005** |
| NXDOMAIN, unsigned, fresh QNAME | **5.005** |

**The 2.005 is the realistic figure**: a resolver sends EDNS0 and most randomize
case. Both remaining allocations are in the *parse* — the question `Vec` and the
QNAME `String` — and nothing on the answering side allocates at all.

The correction *before* that one is kept too, because the pattern is the point.
~~13.7 for a plain query (down from 25.7), 20.7 for the query a real
resolver sends.~~ **Superseded 2026-08-31**, and it is kept rather
than overwritten (§11) because the pair was quoted for a year as *the* cost of an
answer while the shape it under-counted — a case-randomized EDNS query — costs
60% more. What produced the older readings was not bisected; they were taken
under #9e, before #13d moved OPT out of the additional section and before the
two fixes in that same 2026-08-31 commit.

One whole answer — parse, look up, build, serialize — is
**522 ns**, and the `sendto`+`recvfrom` pair around it is **3.6-4.1 µs**. So
everything the benchmark suite measures is about 6% of what a query costs a
server, and a 20% win anywhere in it is worth about 1% end to end. Read
`rdns/benches/answer_path.rs`'s header before quoting any of it.

---

### How to run

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets

# Everything below can go in a TOML file instead, which is the only way to keep a
# TSIG secret out of `argv` and the only way to set anything per zone. The file
# and the flags are mutually exclusive: --config with --port is an error, not a
# precedence rule.
cargo run -p rdnsd -- --config ./rdnsd.toml
cargo run -p rdnsd -- --config ./rdnsd.toml --check-config   # dry run, exits 0
#
#   [server]
#   host = "127.0.0.1"
#   port = 53
#   zone-dir = "./zones"
#   allow-transfer = ["192.0.2.1"]
#   metrics-listen = "127.0.0.1:9153"
#
#   [signing]
#   key-dir = "./keys"
#   validity-days = 30
#
#   [keys."partner.key."]
#   algorithm = "hmac-sha256"
#   secret-file = "/etc/rdns/secrets/partner.key"   # mode 0600, checked
#   zones = ["example.com."]                        # or every zone if omitted
#
#   [zones."example.com."]
#   nsec3 = true              # overrides [signing] for this zone only
#   validity-days = 7
#   masters = ["192.0.2.9#partner.key."]

# Authoritative server, UDP and TCP from one process. The zone origin comes from
# the FILENAME: example.com.zone serves example.com — a mismatch silently yields
# NXDOMAIN for everything. (A config file's [zones."name"] says the origin
# explicitly and does not have this trap.)
cargo run -p rdnsd -- --host 127.0.0.1 --port 15353 --zone-file example.com.zone

# Zone transfers are refused unless an address or a key says otherwise.
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone \
  --allow-transfer 127.0.0.1 --allow-transfer 10.0.0.0/8

# Secondary: replicate a zone from a master. Needs --zone-dir, because the zone
# is written there under its own name. `#keyname` signs the transfer with a key
# --tsig-key defines. Repeat for more zones, or for more masters of one zone.
cargo run -p rdnsd -- --port 15354 --zone-dir ./zones \
  --secondary example.com@127.0.0.1:15353 \
  --secondary other.test@192.0.2.1#transfer.key.

# A TSIG key authorizes a transfer from any address, and signs the answers.
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone \
  --tsig-key hmac-sha256:transfer.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=

# Tell a secondary at once when a zone changes, and cap UDP response bytes/s.
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone \
  --also-notify 127.0.0.1:15354 --response-rate 4096

# Prometheus metrics and the two probes. GET /metrics, GET /healthz (alive) and
# GET /readyz (holds every zone it is configured for); off by default, and with
# no TLS or auth, so bind it somewhere an operator reaches and a client does not.
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone   --metrics-listen 127.0.0.1:9153
# The two alerts worth having, in PromQL:
#   rate(dns_responses_servfail_total[5m]) > 0
#   time() - dns_zone_last_refresh_timestamp_seconds > 604800   # the zone's EXPIRE
#
# /readyz is 503 until every --secondary zone has transferred at least once, and
# 200 immediately on a primary — whose zones were all loaded, signed and verified
# before anything bound a socket. A one-way latch: see rdns/src/readiness.rs.

# The container image. Never built on the Windows side (no runtime there); the `image`
# job in CI builds it, runs it, probes both endpoints and stops it.
docker build -t rdns .
docker run -d -p 53:5353/udp -p 53:5353/tcp -p 9153:9153 \
  -v /etc/rdns/zones:/etc/rdns/zones:ro rdns

# Heap-profile the daemon. Writes dhat-heap.json on exit, which is why it needs
# the graceful stop above — the report is written on Drop. Counts and sizes
# only: it records a backtrace per allocation, so never read a timing from it.
cargo run --release -p rdnsd --features dhat-heap -- --port 15353 --zone-file example.com.zone

# The same numbers as assertions, in their own test binary so the global
# allocator does not slow the other unit tests. One `#[test]` holding eighteen
# measurements, on purpose — `--nocapture` is how you read them.
cargo test -p rdns --test allocations -- --nocapture

# Mutated wire data through everything a stranger's bytes reach before anything
# has authenticated them. 1,506 cases in the suite; these are the soak. Debug on
# purpose — overflow panics in debug and wraps in release, so a release run
# would pass the arithmetic class this is looking for.
RDNS_FUZZ_ITERATIONS=120000 cargo test -p rdns --test no_input_panics -- --nocapture
RDNS_FUZZ_SEED=7 cargo test -p rdns --test no_input_panics

# What a query costs in *time*, on optimized code. Read the header of
# `rdns/benches/answer_path.rs` first: one whole answer is ~0.5 µs and the
# sendto+recvfrom pair around it is ~4 µs, so everything this measures is about
# 6% of a query and a 20% win in it is worth 1% end to end.
cargo bench -p rdns
cargo bench -p rdns -- --save-baseline before   # then change something
cargo bench -p rdns -- --baseline before        # and compare against it

# The two probes, which measure one thing each and are not part of any suite.
# Their headers carry what they measured and when; read those before quoting a
# number. Arguments are the multipliers, so a run is a table row.
cargo run --release -p rdns --example zone_lookup_probe -- miss 100000   # #11, #22
cargo run --release -p rdns --example nsec3_cache_probe -- 150 115       # #23

# Both daemons stop gracefully: SIGTERM or SIGINT on Unix, Ctrl-C/Ctrl-Break/
# console-close/shutdown on Windows. They stop accepting, let the work already
# accepted finish (5s budget), print "drained cleanly", and exit 0 — so an
# in-flight AXFR is not cut, and a client cannot be handed half a zone it
# believes is whole. An idle server stops in about 2ms.
kill -TERM $(pgrep rdnsd)

# Queries per second per source address, its burst, and who is exempt. The
# default is 1000/200; 0 turns the limit off. Rate-limited queries are dropped
# in silence on purpose (a reply to a spoofed source is what an amplifier
# sends), so the effective policy is in the startup banner.
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone \
  --query-rate 5000 --query-burst 500 --query-rate-exempt 10.0.0.0/8

# How many UDP datagrams may be answered at once, which on rdnsd is also how
# many tasks share the socket — there is no task per datagram. Defaults to the
# machine's parallelism clamped to 2-32, costs one 64 KB receive buffer per
# worker, and the effective number is in the startup banner. Past it, datagrams
# queue in the socket receive buffer and the kernel drops the overflow.
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone --udp-workers 4

# The resolver's equivalent, and deliberately a different shape: a recursion is
# seconds of waiting, so rdnsr still spawns per datagram and this is the ceiling
# on how many of those may exist. Over it, the datagram is dropped before it is
# copied. Default 1024.
cargo run -p rdnsr -- --port 15353 --max-inflight-udp 4096

# Ask a running server what it is doing. A Unix socket at mode 0600 — the
# filesystem is the authentication, which is what knotc, pdns_control and
# unbound-control do; there is no control port. Unix only.
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone \
  --control-socket /tmp/rdnsd.sock
cargo run -p rdnsctl -- -s /tmp/rdnsd.sock status
cargo run -p rdnsctl -- -s /tmp/rdnsd.sock dump example.com. > served.zone
# Unlike kill -HUP, this says whether it worked: exit 1 and the parse error if a
# zone file has a typo in it, with the previous zones still being served. Exit 2
# means there was no server to ask, which a deploy script needs to tell apart.
cargo run -p rdnsctl -- -s /tmp/rdnsd.sock reload

# How much either daemon says. info by default; nothing per-packet is above
# debug, so a malformed-packet flood costs no log lines at all (measured: 50
# malformed datagrams, 0 lines at the default level, 50 at --log-level debug).
# --quiet is --log-level error. RUST_LOG wins over the flag.
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone --log-level debug
RUST_LOG=rdnsd=debug,rdns::xfr=trace cargo run -p rdnsd -- --port 15353 \
  --zone-file example.com.zone

# Signing re-signs on a timer now: a third of --signature-validity, and expiry is
# spread over a fifth of the window so the zone degrades on a slope rather than
# expiring all at once. The SERVED SOA serial is not the file's — it is
# file_serial + hours-since-epoch, so a secondary sees each re-signing as a new
# version (see #8). A zone-file edit is also picked up within one interval
# without a SIGHUP.

# Sign a zone. Once, to make the keys and learn the DS to give the parent:
cargo run -p rdnsd -- --signing-key-dir ./keys --generate-keys example.com

# ...then serve, signing every zone there is a key for as it loads. The zone
# file on disk stays unsigned; the signatures live in memory only.
cargo run -p rdnsd -- --port 15353 --zone-dir ./zones --signing-key-dir ./keys

# A zone file that will not parse stops the server: a partial set is how one
# typo becomes a lame delegation with every dashboard green. This serves the
# rest anyway, and says on stderr which zones it gave up on.
cargo run -p rdnsd -- --port 15353 --zone-dir ./zones --allow-partial-load

# NSEC3 instead of NSEC, and refuse to start if anything here is unsigned or
# does not verify.
cargo run -p rdnsd -- --port 15353 --zone-dir ./zones --signing-key-dir ./keys \
  --nsec3 --require-signed

# Resolver, recursing from the root hints. Serves UDP and TCP on one port, and
# binds 127.0.0.1 by default on purpose — not an open resolver.
cargo run -p rdnsr -- --port 15354

# Recursing from a custom root hints file (named.root format) instead of the
# built-in v4+v6 list.
cargo run -p rdnsr -- --port 15354 --root-hints ./named.root

# Same resolver, forwarding instead of recursing.
cargo run -p rdnsr -- --port 15354 --upstream 127.0.0.1:15353

# Validating DNSSEC against the built-in ICANN root anchor. Fails closed:
# an answer that does not verify gets SERVFAIL, not the data.
cargo run -p rdnsr -- --port 15354 --dnssec-validate

# ...or against an anchor file, which is what to use when the root KSK rolls.
# DS presentation format; the digest may be split across whitespace.
cargo run -p rdnsr -- --port 15354 --dnssec-validate --trust-anchor ./root-anchors.txt

# Or let the resolver follow the roll itself (RFC 5011). The file is written as
# well as read: a successor key is adopted after 30 days of publication, and one
# that revokes itself is dropped. Created from the anchors in force if absent.
cargo run -p rdnsr -- --port 15354 --dnssec-validate --auto-trust-anchor ./root.key
```

### Verifying, and one trap that invalidates it

**Check first whether the network hijacks port 53** — a middlebox that answers
every outbound port-53 query invalidates anything measured through it, and the
one-line probe for it is in `CLAUDE.local.md` (untracked: it is a fact about a
network, not about the code).

**That is the case on the development machine**, and it has two consequences
worth knowing before trusting any measurement in this repo:

- **Recursion cannot be verified here.** Iterative (RD=0) queries to the real
  root addresses get SERVFAIL from the interceptor, so `rdnsr`'s default mode
  fails while forwarding works — the interceptor answers RD=1 happily.
- **`--upstream 8.8.8.8` means "whatever answers port 53"**, not Google. Every
  figure recorded here that involved a public resolver was really measured
  against the interceptor.

For local verification, `nslookup` is unreliable against a non-53 port on
Windows — it reports "No response from server" even when the server replied.
Probe with a raw `System.Net.Sockets.UdpClient` in PowerShell and read the
bytes; that is how the "verified live" claims here were checked. (A property of
`nslookup`, not of any one machine, which is why it is here and not in the local
notes.)

### Running the Linux half by hand

CI covers this now, but a session still cannot push (see "Current state"), so
this is how the Linux half gets checked before a commit rather than after one.
Development happens on Windows, so anything `#[cfg(unix)]` is invisible there —
that is how `rdnsd` went months without compiling on Unix, and it is why
`CLAUDE.md` §1 requires the other side to be run before committing anything
cfg-gated.

**The invocation is in `CLAUDE.local.md`**, along with which image, which paths,
how the container image gets built, and the filesystem and toolchain traps that
come with them. Untracked, because none of it is a fact about this project — it
is a fact about one machine, and a checked-in copy of it fails silently on any
other.

What belongs here rather than there, because it is about the *code*:

- **Every Linux number in this file comes from that image**, so the two columns
  in "Current state" are one tree measured twice, not two trees.
- **The permission tests are not affected by where the tree is built.** All three
  write to `std::env::temp_dir()` rather than beside the source
  (`dnssec_key.rs:899`, `persist.rs:289`, `:334`), which is what makes a run from
  a Windows-mounted path trustworthy — a property of the tests, so it changes when
  they do.

**`rdnsc` works against a non-53 port now** (#9f), which it could not before —
that is the reason the recipes here reach for something else. It checks the id
and the echoed question before printing, and falls back to TCP on TC, so it is a
usable first probe even though it is not an independent one:

```sh
cargo run -p rdnsc -- 127.0.0.1:15353 A www.example.com.
```

For an *independent* decode check — our parser agreeing with our serializer
proves little — Node's resolver is c-ares and takes a port in the server string:

```js
const r = new (require('dns').Resolver)();
r.setServers(['127.0.0.1:15353']);
r.resolve4('www.example.com', console.log);
```

**dnspython** (`pip install dnspython`) is
the better tool for anything cryptographic, because its TSIG is interop-tested
against BIND — it signs, verifies, and does AXFR with a keyring, so it can be put
on either side of an exchange. It is *not* a project dependency; it exists so a
third party can disagree with us:

```python
import dns.message, dns.query, dns.tsig, dns.tsigkeyring, dns.name, dns.zone
ring = dns.tsigkeyring.from_text({'transfer.key.': 'BASE64SECRET'})
q = dns.message.make_query('example.com', 'SOA')
q.use_tsig(ring, keyname=dns.name.from_text('transfer.key.'),
           algorithm=dns.tsig.HMAC_SHA256)
print(dns.query.udp(q, '127.0.0.1', port=15353))          # verifies the reply's TSIG
dns.zone.from_xfr(dns.query.xfr('127.0.0.1', 'example.com', port=15353,
                                keyring=ring,
                                keyname=dns.name.from_text('transfer.key.')))
```

A MAC or a signature over a canonical serialization is the one thing that cannot
be verified by both halves of your own code agreeing, so **the signer is checked
the same way**. `dns.dnssec.validate` needs `pip install cryptography` as well;
without it every call fails with "DNSSEC validation requires python
cryptography", which reads exactly like a bad signature and is not one:

```python
import dns.message, dns.query, dns.dnssec, dns.name, dns.rdatatype
zone = dns.name.from_text('example.com.')
ask = lambda n, t: dns.query.udp(
    dns.message.make_query(n, t, want_dnssec=True), '127.0.0.1', port=15353)

r = ask('example.com.', 'DNSKEY')                      # the keys, self-signed
keys = [s for s in r.answer if s.rdtype == dns.rdatatype.DNSKEY][0]
sig  = [s for s in r.answer if s.rdtype == dns.rdatatype.RRSIG][0]
dns.dnssec.validate(keys, sig, {zone: keys})           # raises if it does not hold

r = ask('www.example.com.', 'A')                       # then anything else
data = [s for s in r.answer if s.rdtype == dns.rdatatype.A][0]
sig  = [s for s in r.answer if s.rdtype == dns.rdatatype.RRSIG][0]
dns.dnssec.validate(data, sig, {zone: keys})
```

Three things are worth checking beyond "it verifies", because each is a bug that
still verifies: a wildcard answer's RRSIG must have a *lower* label count than the
name it was served at and must arrive with an NSEC/NSEC3 in the authority section;
an NXDOMAIN must carry two denials, not one; and a delegation's NS RRset must have
**no** RRSIG at all, with the NSEC at that name listing `NS RRSIG NSEC` and not
`DS`.

**The checks CI runs, to run before pushing.** All five pass as of the last
commit; the first four are `CLAUDE.md`'s and the fifth is new with CI:

```sh
cargo build --workspace --all-targets
cargo test --workspace                          # 905 Windows, 921 Linux
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check                                # needs cargo-deny 0.17+
```

~~`cargo test --workspace # 603 + 6 + 85 + 2`~~ — that partition was from before
#31 split the workspace and matched nothing by 2026-09-09. The two numbers are
the whole-workspace totals, and the gap between them is §1's tell: Linux
compiles `rdnsd/src/control.rs` and the rest of the `#[cfg(unix)]` half, which
is 13 tests in `rdnsd` and 3 in `rdns`. They were 907 and 923 until #38, which
deleted 15 tests of code nothing called and added two for the DO bit.

**`CLAUDE.md` has a sixth check that CI does not run**: `cargo doc --workspace
--no-deps`, clean since 2026-09-09 and held there by nothing but somebody typing
it. Adding it to `ci.yml` is a step in an existing job rather than a new
job-run, so it costs no extra minutes — the owner's call, like every other
change to what a push does.

`cargo deny` on an older version dies with "unknown variant `2024`" — eleven
crates in the graph are edition 2024 and 0.16's manifest parser predates it.
0.20.2 is what these numbers were taken with. CI also builds on **1.95 exactly**
(the pinned MSRV) and with `--features dhat-heap`, neither of which the commands
above cover.

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

~~Two sections: **#37**, which is open work, and **#21**, which is an inventory
rather than a queue.~~ ~~**One section as of 2026-09-08**, #37 having closed the
day it was filed: **#21**, which is an inventory rather than a queue.~~
~~**Two again as of 2026-09-09**: **#38**, whose five open sub-items are cleanups,
and **#21**, which is an inventory rather than a queue.~~ ~~**Four as of
2026-09-10**: **#38**, one sub-item of which is left, **#39**, the answering
path's shape, **#40**, the joints between the internal APIs, and **#21**, which
is an inventory rather than a queue.~~ **Two as of 2026-09-11**, #38 having closed
on 2026-09-10 and #39 on 2026-09-11: **#40**, ~~two sub-items of which are left
(40d, 40f)~~ **one of which is left (40f)**, and **#21**. Everything
else numbered is under "Closed work" below — except #38's and #39's sections,
which are closed and still sit here rather than in `docs/CLOSED_WORK.md`; their
rows in that table say so.

### Where to pick up next

Everything here is a choice, not a queue. ~~One thing, with #33 and #34 both
closed~~ — that was the state on 2026-09-07; ~~**#37 was filed on 2026-09-08** and
is the only numbered work open.~~ ~~It is still a choice: 37a is worth taking on
its own~~ — 37a was taken the day it was filed, because checking its own open
question turned it into a defect report. ~~**37b-37d are what is left**~~ —
~~37b and 37c were taken on 2026-09-08 too. **37d is what is left**, and it is
explicitly "when that code is next opened".~~ ~~**All four were taken on
2026-09-08**, so nothing numbered is open and this heading has nothing under
it.~~ **#38 was filed on 2026-09-09** and five of its sub-items are open, so
this heading has something under it again — for a day, at least.
The four strike-throughs above are one day's worth, which is the argument for
this heading being short: a paragraph naming what is next is wrong as soon as
somebody does it.

~~**Of #38's five, take 38d's `rdnsr` half first.** It is the only one that has
never had the judgement made about it: `rdnsd` was split in #20 and the decision
not to split it further was taken deliberately, while `rdnsr` simply never got a
first split.~~ **Taken 2026-09-09**, the day after it was filed; the row says
what the split was and what it measured. ~~**38a and 38c are moves with no
behaviour in them**~~ (**38c taken 2026-09-10**, and it was not a move with no
behaviour in it: it deleted three things nothing called and found four symbols
`docs/spec/` names that do not exist), ~~**38b is a small operational gap**~~
(taken 2026-09-10), and ~~**38e is half an hour**~~ (taken the same day, and it
was two hours: the count came out at eight instances rather than three) —
~~and 38d's other half, `rdnsd`'s fourth seam, is the one #20 already decided
against once, so it wants an argument rather than a session.~~ **The argument
was taken 2026-09-10**: the row carries the measurement, and it turned up the
API shape that decides it — **#39**, one dispatcher instead of two. ~~Take #39
first; 38d falls out of it.~~ ~~**39a and 39b are done (2026-09-10)**, and
38d went with them, so #38 is closed and what is left is 39c, 39e and #40.~~
**#39 closed 2026-09-11**: 39c and 39e went on 2026-09-10, 39d on 2026-09-11.
~~**#40's 40d and 40f are what is left**, and neither is a defect — one is twelve
modules with no membership rule, the other is two caps with no flag and a
measurement to take before adding one.~~ **40d went the same day and 40f is what
is left**: two admission caps with no flag, and §14's own warning to measure what
a legitimate UPDATE weighs before adding a knob. 40d was not a defect either, but
its second half deleted six silent `continue`s by typing one map key — which is
the §17 argument, and the correction 40a's row now carries.

One candidate named elsewhere on this page, for a session that wants it:
**SVCB/HTTPS presentation form** was the largest remaining entry in #21's
not-implemented list and closed as #35; ~~**#13e's `Name` half**~~ closed as #36
on 2026-09-07, so both of the two named here are gone. Not a queue either.

> **1. ~~Push, and~~ read the five CI jobs nobody has ever read.** ~~Ask
> `git rev-list --count origin/main..HEAD` how much is waiting; it was 49 on
> 2026-09-05.~~ **Pushed 2026-09-09 at `acd229e`**, so the count is 0. Reading
> the runs is what is left, and a session cannot do it from here: there is no
> `gh` on this machine. Of the seven job-runs a push costs, five have
> never been looked at: msrv (1.95), deny, the container image, the `dhat-heap`
> feature build, and clippy on *Linux* — though that last one is checked by hand
> here and is clean as of ~~2026-09-06~~ **2026-09-08**, on the half of the tree
> Windows cannot compile. **This is the owner's call and not a session's**:
> `CLAUDE.local.md` says why a push costs something and who makes it.
>
> The last run that was read was the first one, on 2026-08-01, and it found two
> things — a Windows test that was wrong rather than code that was, and
> `actions/checkout@v4` on a runner that had moved to Node 24. Both fixed in
> `8758476` and ~~unpushed since~~ **pushed 2026-09-09**, five weeks later.
>

**Read `benches/answer_path.rs`'s header before quoting anything from it.** One
whole answer is 522 ns and one `sendto`+`recvfrom` pair is 3.6-4.1 µs, so the
entire benchmark suite covers about 6% of what a query costs — the context that
stops a 20% win in it being reported as a 20% win.


---

### 40. The internal APIs, asked whether they fit each other — **filed 2026-09-10**

Asked for after #39: a pass over the *joints* rather than the modules — where one
module hands a value to another, is the type at the joint the right one. Nothing
here is a live defect; every item is a shape that lets a wrong call compile.
The measurements are in each row, taken before anything was edited (§18).

| | | |
|---|---|---|
| ~~**40a**~~ | ~~three encodings of a name, one type~~ **two of the three typed 2026-09-10; the third measured and declined** | A name is used as a map key in **21 maps** across 7 modules, in **three incompatible encodings**: folded wire octets (8 maps), RFC 4034 §6.1 canonical sort order (7), and the NSEC3 owner hash (2). Four of the 21 carry a type — `NameKeyBuf`/`NameTypeKey`, which #38a built for the folded meaning; the other 17 are `Vec<u8>`, `Box<[u8]>` or `(Vec<u8>, Rtype)`. The sharpest instance is one file: `zone_signer.rs:348`/`:350` is `BTreeMap<(Vec<u8>, Rtype), _>` keyed by *folded owner*, `:868` is the same type keyed in *canonical order*, and `sign_everything` holds both at once — it builds the canonical-order map at `:889` and calls `previous.reuse` at `:913`, which re-derives a folded key at `:424`. Nothing but the argument type keeps them apart. `nsec_cache::insert_bounded` (`:922`) takes `&mut BTreeMap<Vec<u8>, _>` and is called with both the canonical-order map and the hash map, because at that type they are the same map. §17: newtype them and the wrong one stops compiling everywhere at once. **The limit to respect**: the point of the canonical key is its `Ord`, and `NameKeyBuf`'s `Ord` is byte order over folded wire, which is *not* canonical order — three types, not one, and `Layout`'s doc (`zone_signer.rs:657`) already says why `Name` has no `Ord` at all. **Three shapes were built and measured before any was kept.** *`CanonicalKey`* (5 files, +51/−31) is the cheapest and the most surgical: every probe already built an owned key, so no allocation moved, and it needs **no `impl` block at all** — nothing outside `denial_wire` wants the octets, and the one test that pins the encoding lives in that module and constructs the newtype directly. *`Nsec3Hash`* (9 files, +163/−122) is the one with a defect behind it and the only one that *deletes*: `covers_hash`'s `is_empty()` guard, `use std::ops::Bound` in two files with the turbofished `range::<[u8], (Bound<&[u8]>, Bound<&[u8]>)>` it existed for, and 13 `clone()`/`to_vec()` calls, after which clippy offered a `sort_by_key` the `Vec` had forbidden. It costs `.as_bytes()` at 23 sites, all at wire boundaries. **Either one forces the same fix**: `Zone::chain_key` returned `(Chain, Vec<u8>)`, whose second element meant whichever the first said, and the compiler refuses that tuple the moment *one* half is typed — typing one side of a confusable pair is enough. Both landed. **The third, a `NameKeyBuf` sweep of the 8 folded maps, is declined**: 12 of the 14 raw-keyed maps are private fields, so with the two typed there is no scope left where two encodings meet, and it is the one that would need `Borrow<[u8]>` on the hot probe path — the hole that lets an untyped slice back in. ~~Declined whole~~ **— the decline holds for the 12 and did not cover the rest, corrected 2026-09-11 with 40d**: the two that were *not* private fields are `pub(crate)` type aliases (`ZoneMap`, `Secondaries`), a third crate-visible leak was an accessor rather than a map and so was never in the count, and all three are now typed. The `Borrow` objection did not apply to them either — `NameKeyBuf` already has `Borrow<[u8]>` and both hot probes already went through it. Counting declarations and not their visibility is what §19 was written about, and this row is the one that took the visibility measurement. **No allocation count moved** either way, on either platform; the win is deletions and two length checks, and assuming otherwise is what §17 says to measure |
| ~~**40b**~~ | ~~`(Name, Qtype)` and `NameTypeKey` are one key under two names~~ **the filing was wrong; checked and declined 2026-09-11** | ~~`nsec_cache`'s `wildcards` is `HashMap<(Name, Qtype), CachedWildcard>` (`:53`); `cache` and `negative_cache` spell the same key `NameTypeKey`. 38a converted three maps and this is the fourth, missed because it is a tuple rather than a named type and so did not match the shape being counted.~~ **It was not missed, it was chosen, and the reasoning above is the defect.** The two spellings are two idioms with a criterion: `Name`'s `Hash` and `Eq` fold the same ASCII octets the same way (`name.rs:500`), so both are correct about case, and what decides is what the probe holds. `NameTypeKey` exists for lookups that already have wire octets and would otherwise build a `Name` to throw away — `name_keys.rs` says so, in the `Borrow` argument. The wildcard probe is the other case: `*.<parent>` is nowhere in the query, so `wildcard_for_parent_of` *constructs* the key, which makes the allocation the key's shape rather than its type; a folded key would keep it and add a fold and a `dyn` call. Converting is a wash at best. **Done instead**: the criterion is written where it will be read, in `name_keys.rs`'s header and on the `wildcards` field. The reasoning is left above rather than edited away, because it is the reasoning that produced the wrong filing (§11) — it counted declarations and inferred an oversight, never opening the probe that shows it was a decision |
| ~~**40c**~~ | ~~`Transport` sits one crate above the decision it makes~~ **done 2026-09-10** | ~~`rdns_transport::Transport` exists because "one `is_tcp`" was answering three questions (`rdns-transport/src/lib.rs:36-39`), and then `ServeContext::admit` converts it back — `self.validator.validate_packet(packet, transport.is_tcp())` at `:140` — because `rdns_core::validation::Validator::validate_packet` still takes `is_tcp: bool` (`validation.rs:163`). One call site, and the enum has no dependencies, so it can live in `rdns-core` beside the validator and be re-exported where it is now; `is_tcp()` then has no callers.~~ **Done**: the enum is `rdns_core::validation::Transport`, `validate_packet` takes it, `is_tcp` is deleted, and the four crates that named `rdns_transport::Transport` now name `rdns::validation::Transport` — one spelling rather than a re-export, since nothing outside the workspace depends on the old path. 8 files, no behaviour: 905 tests on Windows and 921 on Linux, before and after |
| ~~**40d**~~ | ~~twelve library modules state no membership rule~~ **done 2026-09-11** | No `//!` anywhere in the file and no doc at the `mod` declaration: `rdns-core/{dname,validation}`, `rdns/{cache,logging,security,zone}`, `rdns/zone/{checks,parse,rdata}` and all three of `rdns/resolver/{caches,recurse,validate}`. #38c's whole fix for `utils` was "seven modules, each stating its membership rule", and #37's argument for a folder is the same argument. Beside it, the inverse: `rdnsd/src/zones.rs:34` documents `ZoneMap` as "keyed by its origin in `rdns::name_keys::NameKeyBuf` form" while the type is `HashMap<Box<[u8]>, Arc<Zone>>`, and `zone_key` (`:44`) exists so "no call site keys on `origin().to_string()`" — an invariant held by a convention and asserted in a doc comment, which §17 says is a claim to verify, not documentation to trust. 40a's fix is what makes it true **Done, both halves, and it was fourteen files.** The twelve are confirmed — the `//!`-less files in the workspace were exactly those twelve plus `rdnsd`'s and `rdnsr`'s crate roots. The roots were going to be left, on the argument that what a *binary* is gets said by clap's `about` and by "How to run" above; the measurement that killed that is one command, because `rdnsc` and `rdnsctl` both have a crate header — two of the four binaries had already decided, so the exception was one file's habit and not a rule. Every `.rs` file in the tree has one now, tests and benches included. **The measurement that could have refuted it** (§19) was whether the rule is stated somewhere else: it is not — both crate roots' `//!` document the *crate* boundary (`rdns` against `rdns-core`) and neither is a module map, and none of the twelve had a doc at its `mod` line either. Each header now says what belongs and, where it is the interesting part, what does not: `validation` is the three questions answerable from the packet alone and not who sent it, `security` the three policies keyed on an address that is not an identity (§16), `zone/checks` the rules with no correct query-time answer *and* the boundary that they are a message to an operator rather than an invariant the answer path may lean on, since a zone arriving by transfer or UPDATE never meets them. **The `ZoneMap` half turned out to be the one instance of 40a's declined sweep worth taking**, and taking it found six sites: `ZoneMap` is now `HashMap<NameKeyBuf, Arc<Zone>>`, and the six `NameRef::from_wire_slice` re-derivations of a key went with it — **every one of which skipped the zone in silence** on an `Err` that cannot happen (`continue` or `.ok()`), so a key that failed to read back meant a zone not signed, not verified under `--require-signed`, not journal-restored, not withdrawn by a reload, not counted, and a `deepest` walk too short to find it at all. Not live defects — the `Err` is unreachable by construction — which is the point of §17: the type makes the unreachable branch *unwritable*, where `Box<[u8]>` made six authors write it six ways. **Zero churn at the 22 insertion sites**, since all of them already went through `zone_key`, and none on the hot probe, since `NameKeyBuf`'s `Borrow<[u8]>` already existed and `Zones::for_query` already probed with a folded `Cow`. **Counting the shape (§18) found two more**, both taken: `Secondaries`, the same `pub(crate) type` alias, whose insertion and NOTIFY probe each folded by hand under two comments asserting they agreed; and `PlannedDelta::zone`, the one `pub` accessor handing raw folded octets across a crate boundary, whose single consumer re-derived the name with a seventh silent `if let Ok`. The three together delete `ixfr`'s private `key()` helper and four `as &[u8]` casts, which were the shape of an untyped key leaking into a probe. What stays declined is 40a's set and for 40a's reason: the three remaining raw-keyed maps (`Zone::index`, the resolver's delegation and key caches) are private fields whose `Borrow` probe is the point. No behaviour and so no new test: 908 tests on Windows and 924 on Linux, the same before and after on each, clippy and `cargo doc` clean on both. One existing test's doc was wrong and is corrected — `one_origin_in_two_cases_is_one_zone` said "the key type is what upholds it", which was true of `zone_key`'s convention and not of the type until now |
| ~~**40e**~~ | ~~the tail of #38's `pub` sweep~~ **done 2026-09-10** | ~~#38 measured `rdns/src` and narrowed 87 items; it did not look at the other crates. Of the 112 top-level `pub` items in `rdns-core` and `rdns-transport`, **3** are named nowhere outside their own module — `AdmissionLimits` and `ValidationResult` (`rdns-core/src/validation.rs:105`, `:124`) and `listener_failure` (`rdns-transport/src/lib.rs:286`). Small, and the point of recording it is that the sweep was crate-shaped and the crates it skipped are now measured. Beside it, one stale claim: `rdns/src/lib.rs:7` still says `rdns::utils` "names what it always did", and #38c deleted `rdns-core::utils`.~~ **Done, and the compiler decided it the way it decided #38's**: `AdmissionLimits` and `AdmissionCheck::new` are `pub(crate)` and `listener_failure` is private, while **`ValidationResult` stays `pub`** — narrowing it is a private-in-public error, because `validate_packet` returns it and `rdns_transport` calls that. The sweep now reads 1 of 110, and the one is justified in a comment. The stale `rdns::utils` line is gone. **40f is what narrowing `AdmissionLimits` exposed** |
| **40f** | the two admission caps have no flag | `AdmissionLimits` is 512 octets on UDP (RFC 1035 §4.2.1) and a 16 KiB ceiling this codebase chose for TCP, and 40e established that nothing constructs one: `AdmissionCheck::with_defaults` is the only way in, so neither cap can be changed without editing the source. §14 is the rule — a limit with no flag is a limit nobody has reviewed — and the `pub` struct that stood where a flag should be was not an answer, because no caller ever built one. The UDP cap is the one an operator might have to move: it is a *request* cap, and a signed UPDATE or a TSIG'd NOTIFY over UDP is not obviously under 512 in every deployment. Measure before adding a knob (§14's own warning about knobs that turn the server off): what does a legitimate UPDATE actually weigh |

**What this pass checked and found sound**, so the next one need not: the two
`error` modules are a deliberate joint, not a duplicate — `rdns::error`
re-exports `rdns_core::error::*` and adds only the two types that need a `tokio`
`From` impl, and the header says so. `absolute` appears five times and is one
implementation: `rdns-core::text_names::absolute` plus four aliases, each a
one-liner whose doc points at it. ~~`rdns-core`'s `lib.rs` already documents the
`macro_rules!` ordering trap that #39d hit in `rdnsd`.~~ **Wrong, and the only thing
this pass called sound that was not: documenting a trap is not escaping it.** The
same fix applied there, and it went with 39d on 2026-09-11. And two of `CLAUDE.md`
§17's "smells, all currently in this tree" are no longer in it: `num_derive` is
not a dependency of anything in the workspace, and OPT is a field of
`DnsMessage` rather than a record in `additionals` — both closed with #13, whose
row says so. §17's list wants that correction the next time it is opened.

---

### 39. `rdnsd` answers through two dispatchers — ~~**filed 2026-09-10**~~ **closed 2026-09-11**

Found by taking 38d's measurement: the two items that would not seal are the two
the root's dispatchers call, so the split is bounded by the answering path's
shape rather than by where the code sits. `rdnsr` already has the shape this
asks for — `handle_query` is one dispatcher taking `transport: Transport`, both
socket loops call it, and `finish` (`rdnsr/src/answer.rs:324`) is the single
epilogue, shaped by a `Client` (`:64`) carrying the EDNS, the AD wants and the
size ceiling. `rdnsd` has `Server::answer` (`main.rs:725`, TCP) and
`Server::answer_datagram` (`:1590`, UDP), the same prologue written twice — the
UDP copy's own comment says "now literally the same code".

| | | |
|---|---|---|
| ~~**39a**~~ | ~~the prologue has drifted, and a counter is the casualty~~ **done 2026-09-10** | ~~TCP counts `queries_received` and tracks the qtype at `main.rs:750`/`:752`, *before* the TSIG check at `:757`; UDP does both at `:1666`/`:1668`, *after* the check at `:1641`, which returns early on a rejection. A TSIG-rejected request is a received query over TCP and is not one over UDP, and the qtype histogram gets it on one transport only. §14: a counter's name is a claim about what it counts. The defect in this section; the rest is shape.~~ **Fixed**: the UDP path counts where the TCP path counts, before any policy can return, so the two prologues are now identical up to the TSIG check — which is what 39b merges. The test asserts both counters on both transports and was watched failing against the old order (the UDP half read 0). 906 tests on Windows, 922 on Linux, one more than before on each |
| ~~**39b**~~ | ~~one dispatcher, with the transport as a parameter~~ **done 2026-09-10, shape A** | What varies across the two loops is three things, each already written twice: the frame (length-prefixed vs bare — the UDP UPDATE path strips the prefix by hand at `main.rs:1676`, `framed.get(2..)`), the ceiling (`u16::MAX` vs `udp_payload_size()`, which #30g recorded as the *only* difference between two copies of the error reply), and the response budget with its TC=1 fallback, which is UDP-only. A sink owning those three is the whole parameter — not `rdnsr`'s `Transport` enum, because `rdnsd`'s TCP path streams a sequence of AXFR envelopes into an `mpsc` while `rdnsr` returns one datagram. **Closing this closes 38d**: with the dispatch inside the module, all nine items seal instead of seven. **Three shapes were built and measured on 2026-09-10**, each compiling, clippy-clean and passing all 119 `rdnsd` tests, so none of them is decided by whether it works. Baseline: `main.rs` 1691 non-test code lines, the two dispatchers 229 of them. **(A) an enum sink** `Wire::{Framed(&Sender<Reply>), Datagram(&UdpSocket, SocketAddr)}` carrying `max_len` and `send` — 1620 lines. **(B) a `Wire` trait** with two impls — 1619. **(C) no sink**: the dispatcher takes `transport: Transport` plus `out: Option<&Sender<Reply>>` and *returns* `Option<Cow<[u8]>>`, the loops sending — 1601, the smallest. **A is the one to take**, and the 19 lines it costs over C buy three things C and B do not have. *One value that cannot disagree with itself*: C's two parameters can — a caller passing a sender with `Transport::Udp` streams a zone into a datagram loop and nothing there can tell — where A's single `Wire::Framed` **is** both facts, which is also what turns "a transfer is TCP-only" from `answer.rs:140`'s comment about which caller got here into a branch the compiler sees. *The send stays inside the unit under test*: under C `answering_a_second_datagram_reuses_the_first_one_s_buffer` **hung the suite** — its closing assertion is that the reused buffer "really carried an answer to the wire", and with the send moved out to the caller nothing arrived; it had to be rewritten to do the loop's job itself, which is a regression test losing its teeth. *And B is an enum wearing a trait*: asking "can this transport carry a sequence" needs a `fn sequence(&self) -> Option<&mpsc::Sender<Reply>>`, so the TCP type reappears in the vocabulary of the abstraction meant to hide it — and without a fourth method for "are you budgeted" B quietly put TCP replies through the UDP response budget, **with all 119 tests still green** (§1, live). A also gets `match` exhaustiveness the day a third transport arrives. All three delete the `&framed[2..]` hack, because all three make `transfer_error` return unframed bytes — which is 39c, and it fell out of every one of them. **Landed**: `main.rs` 1691 non-test code lines → 1620, the two dispatchers' 229 → 161 as `Wire` + the `Handler` impl + `answer` + `finish`. `transfer_error` takes a ceiling and returns unframed bytes, so `update_reply` and `answer_update` return `Option<Vec<u8>>` where they returned a `Vec` that was always 0 or 1 long, and the UDP UPDATE path's `framed.get(2..)` is gone. The UDP hot path keeps its `Cow::Borrowed` out of the worker's scratch. One new test, because **nothing covered AXFR or IXFR over UDP at all** and the merge is what makes that branch reachable from a datagram: FORMERR for AXFR (RFC 5936 §4.2), one SOA for IXFR (RFC 1995 §2), watched failing against a gate that trusts the caller. 907 tests on Windows, 923 on Linux |
| ~~**39c**~~ | ~~the error reply is one function with a ceiling~~ **done 2026-09-10** | `error_bytes`, `truncated_reply`, `send_transfer_error` and `update_reply` — which is `transfer_error` under another name — all build "an empty reply carrying this rcode, at this ceiling, signed if the request was". §7's "two functions building the same kind of message are one function with a parameter", and #30g said the ceiling was the difference. `error_bytes` is stuck in the root today only because both the cluster and the dispatchers call it. ~~**Half of this landed with 39b**: `transfer_error` now takes `max_len` and returns unframed bytes, and `update_reply` is a one-line call to it. What is left is the consolidation proper — `error_bytes` and `truncated_reply` are still two functions building an empty reply at a ceiling, and `update_reply` is still a name for `transfer_error`.~~ **Done**: `empty_reply` is the shared part — echo the question, mirror the client's OPT with its DO bit — and `error_reply` and `truncated_reply` are the two things you can then set, each taking the ceiling. Not one function with a `truncated: bool`: the two names carry the difference and a bool at a call site would not (§17's limit on typing everything). `update_reply` is gone and `transfer_error` is `signed_error`, since it was never only the transfer's. **The ceiling now has one source**: `wire.max_len(&msg)` is read once per request and threaded to all four users, so the UPDATE path stopped hardcoding `u16::MAX` on a datagram and `truncated_reply` stopped deriving its own. The OPT test covers `error_reply` too now — it did not before — and was watched failing against a hand-rolled mirror, which is the drift it exists to catch. 907 on Windows, 923 on Linux, unchanged |
| ~~**39d**~~ | ~~the two log macros pin the module order~~ **done 2026-09-11, and it was two instances** | `bad_request!` (`main.rs:90`) and `serving_error!` (`:102`) are `macro_rules!`, so textual scoping forces `mod transfer;` below line 107 — found by hitting it. `pub(crate) use serving_error;` after each makes them ordinary imports, order-independent, without `#[macro_export]` widening them to the crate's public surface. **Done**: both are re-exported that way and `dispatch` imports them like any other item. **Counting the shape first (§18) found a second instance, which this section's own sibling had filed as sound**: `read_be!` in `rdns-core`, whose `#[macro_use] mod macros` carried the trap as a comment — "Declared after `macros`, because `#[macro_use]` on a module makes its macros visible only to what follows it". Documenting an ordering constraint is not escaping it. Same fix: `pub(crate) use read_be;`, a `use crate::macros::read_be;` in each of the two users, and the module in its own file with the `//!` 40d wants. `mod macros;` now sits in the alphabetical list like any other module instead of ahead of the users it had to precede — the list is sorted rather than ordered, which is the whole of what this buys in that crate. `rdnsd`'s half is the one that demonstrates it: `mod dispatch;` moved from `main.rs:107` to `:7`, *above* the macros it used to have to follow. The third `macro_rules!` in the tree — `recv!` at `rdns/src/shutdown.rs:188` — is function-local and constrains nothing. No behaviour: 908 tests on Windows and 924 on Linux, the same counts before and after on each, clippy clean on both, `cargo doc` clean |

| ~~**39e**~~ | ~~`tcp::Handler` has nowhere to keep per-connection state~~ **checked 2026-09-10, and not worth doing** | The UDP worker reuses one `Scratch` — reply buffer, name compressor, folded key — across every datagram it answers; the TCP path builds a fresh `Vec`, a fresh `NameCompressor` and a literal `&mut String::new()` per message, because `rdns_transport::tcp::Handler` takes `&self` on a `Server` shared by every connection and has no state of its own. Not a regression and not new — it is what the 39b experiment made visible, since the merged dispatcher takes a `&mut Scratch` and TCP has to conjure one per call. ~~A `Handler::State` created per connection is the shape; the measurement to hold it to is `tests/allocations.rs` plus `benches/answer_path.rs`, and the reason to be careful is that the trait is `rdnsr`'s too.~~ **The shape is wrong and the size is small.** `tcp::Handler::handle` is `tokio::spawn`ed *per message*, capped by a semaphore at `max_inflight_per_connection` (16), so that a pipelining client's next query is read while the last one is answered — up to 16 handlers for one connection run at once and no `&mut` can be handed to them. The shape that would work is "the permit carries the buffer": replace the semaphore with a pool of `Handler::Scratch`, one per in-flight slot, acquired instead of a permit. That needs an associated type on a trait `rdnsd`, `rdnsr` and the transport's own test handler all implement. **What it would buy is 3 allocations per TCP message** — the output buffer and the compressor's two — now measured and asserted in `rdns/tests/allocations.rs` beside the warm case's 0, so the number cannot drift unnoticed. Against that: TCP on an authoritative server is the fallback path, and its biggest consumer does not touch the scratch at all — `answer_transfer` serializes each envelope into its own `Vec`, at 9-20 allocations per envelope of which the buffer is one, and the compressor genuinely has to be fresh per message because a pointer addresses an offset inside its own. **Checked and wrong on the way**: each envelope looked like a 64 KiB allocation from `to_bytes_within(u16::MAX)`, but #25b already sizes the scratch to `wire_size_bound().min(max_len)` |

**Rejected, with the measurement**: a narrower context struct for the transfer
and UPDATE cluster, on `ZoneContext`'s precedent. The cluster touches 6 of
`Server`'s 8 fields (`ctx`, `zone_map`, `updates`, `deltas`, `transfer_acl`,
`journal`), and the two it does not need are the door's (`tsig_keys`) and
NOTIFY's (`secondaries`). A `TransferContext` would be `Server` minus two
fields: a rename, not a seal.

**The cost to hold honest.** The UDP dispatcher is the hot path: the ordinary
answer is sent as a `Cow::Borrowed` straight out of the worker's scratch buffer.
A sink that forces an owned `Vec` per reply pays an allocation per query.
`tests/allocations.rs` and `benches/answer_path.rs` are the guards — §17's rule
that "zero-cost" is a claim about a compiler, not a fact about a diff.

---

### 38. A structural review, and what it left — **filed 2026-09-09**

Asked for as "inspect the codebase for organization, best practices,
duplication and structure", so this is the review's own record: what it found,
what was fixed the same day, and what is filed. **Nothing here is a defect
report** — the one defect it turned up (a dropped DO bit) is in the fixed half.

**Fixed, three commits:**

- **`pub` was the default rather than a decision.** `rdns/src` held 571 `pub`
  items against 18 `pub(crate)` and 26 `pub(super)`. Measured the way #37 says
  to measure a split — visibility, not line count — 87 of them were named
  nowhere else in the workspace, tests, benches and examples included. Narrowing
  all 87 and letting the compiler sort them: 16 stay `pub` because a public
  signature reaches them, 6 became `#[cfg(test)]` because only their own tests
  called them, and the rest are private. `dead_code` then found what nothing
  called at all — 14 items and the 12 tests that were their only callers, which
  is §1 from the other direction: a test for a function no caller has proves the
  function, not the system.
- **The reply epilogue was written three ways in one binary.**
  `ClientEdns::mirror` decides whether a reply carries an OPT and with which DO
  bit (RFC 6891 §6.1.1, RFC 3225 §3); `rdnsd/src/answer.rs` used it, while
  `truncated_reply`, `error_bytes` and `rdnsr`'s `unsupported_opcode` wrote
  `has_edns()` plus a fresh `Edns` and dropped the bit. A validating client over
  budget got TC=1 with DO clear, and the two daemons' NOTIMP replies disagreed.
  `ClientEdns::of` is the total constructor those paths need; both regression
  tests were watched failing against the old behaviour.
- **#5 of the review, and the line #37a closed with**: the DNSSEC structs still
  held names as canonical text. Eight `String` fields became `Name`, the
  `proves_*` family and the denial cache took `NameRef`, and
  `utils::{label_count, suffix_labels, is_at_or_under}` were deleted for want of
  a caller. A validator's signed NXDOMAIN went from 4 allocations to 1 under
  NSEC and 2 to 1 under NSEC3; dnspython validated both chains off a live
  `rdnsd`, including `a\.b.example.com.` — one label with a dot in it.

**Open, and each is a cleanup rather than a queue:**

| | | |
|---|---|---|
| ~~**38a**~~ | ~~three things still key on folded text~~ **done 2026-09-10** | ~~`negative_cache` (`NameKeyBuf` + `NameTypeKey`), `cache` (`(String, Qtype)` with the `Borrow` trick) and `metrics`’s zone gauges. All three are allocation-free on the lookup path today — `allocations.rs` asserts 0 for a miss in either cache — so the win is uniformity, not speed, and the cost is that `HashMap<Name, _>` cannot be probed by a `NameRef` without the same `dyn` trick these use for `&str`.~~ **That claim was the file’s, not the path’s**: every count in `allocations.rs` hands the cache a `&'static str` already in key form, while `rdnsr` spells the lookup `get(&qname.to_presentation(), qtype)` — measured at 1 allocation per probe, two per query before a resolution and two more on the store. Now 0. The keys are folded wire octets in `rdns-core::name_keys`; `Borrow<[u8]>` needs no `dyn` for the name-only map and no transmute for either; the RFC 8020 ancestor walk is `NameRef::parent()`, which borrows. A name in mixed case costs one allocation for the fold, once for the whole walk. `text_names` keeps only what a zone file needs, `parent_name` and `separators` having lost their last callers |
| ~~**38b**~~ | ~~a removed zone's journal is never deleted~~ **done 2026-09-10** | ~~`journal::journalled_zones` read the directory "so a journal left by a removed zone is found and cleaned up instead of resurfacing if that zone is ever re-added". Nothing called it: `zones::restore_journals` walks the *zone list* instead, so an orphan journal stays on disk until somebody notices. Deleted with the rest of the dead code rather than left as a function nobody calls; the gap is here because deleting it would otherwise have deleted the finding~~. `journalled_zones` is back as a `Journal` method, and `zones::discard_orphan_journals` deletes what no zone claims, once, at startup. Startup is the whole of it: a reload already forgets the journal of a zone it withdraws, so the only way to leave one behind is to remove the zone while the process is down. The two EXPIRE paths deliberately keep theirs — the copy on disk did not change while contact was lost, so the history still reaches the serial that loads. Under `--allow-partial-load` a zone whose file will not parse loses its journal, which is the right way for it to fail and is written down where it happens |
| ~~**38c**~~ | ~~`rdns-core::utils` is the crate's miscellany~~ **done 2026-09-10** | ~~783 code lines and seven unrelated things: the RR-type and QTYPE tables, the SVCB parameter keys, hex/base64/character-string codecs, the presentation-name helpers, `bind_addr_for` and `recv_error_is_transient`, the clock, and `dname_redirect` — which is RFC 6672’s substitution rule and not a utility at all. #37d’s argument applies (a name that says what is in it, and private helpers held at `pub(super)`), but the visibility measurement is small: four private items.~~ The measurement that decided it was a different one: **15 of the 30 public items had no caller inside `rdns-core`**, so "shared across the crate", which its doc claimed, was false for half of it. `utils` is deleted. Seven modules, each stating its membership rule: `record_types`, `codecs`, `clock`, `socket`, `text_names` (whose doc says it exists so 38a has something to delete), plus `dname_redirect` to `name`, `rand_id` to `message`, the SvcParamKey tables to `rdns::svcb` and the UDP receive helpers to `rdns-transport`. Along the way: `presentation_labels` and its iterator had no caller anywhere (60 lines), `record_type_code` was `rdata.rtype()` with a function around it, and `test_record_types_constants` asserted `A == A` thirteen times. **And `docs/spec/` named ten `utils::` symbols of which four did not exist** — three from earlier dead-code sweeps, one from this one; `cargo doc` cannot check a Markdown file, which is why they sat there |
| ~~**38d**~~ | ~~the two daemons are cut on different principles~~ ~~**`rdnsr` split 2026-09-09; `rdnsd`'s half is what is left**~~ **both halves done, `rdnsd`'s 2026-09-10** | `rdnsd/src/answer.rs` holds the *query* path (391 SLOC) and 559 SLOC of AXFR/IXFR/UPDATE/NOTIFY answering stayed in `main.rs` as `impl Server` — a fourth seam of the kind #20 lifted three of, and #20 said explicitly it was not worth going further, so taking it means arguing with that rather than repeating this. ~~That judgement was never made for **`rdnsr`, which has no modules at all**: 773 SLOC of CLI, the RFC 5011 anchor manager (~180), the answer path, the UDP loop and `main` in one file, and its AD-bit policy spelled out at five call sites.~~ **Done**: `anchors` (the RFC 5011 manager), `answer` (the caches and the answer path), `serve` (the two socket loops) and `testutil`, leaving 300 SLOC of CLI and `main`. Measured the way #37 asks — visibility, not line count — eight items that were visible to the crate root and every descendant — five in `answer`, three in `anchors` — are now module-private, and `Caches`'s three fields have a constructor in front of them; `serve` seals nothing and is the one split made for the seam alone. The AD-bit rule is `finish`'s, once, with a test for all four combinations. 769 non-test SLOC became 813, the difference being four `use` blocks where there was one. **The measurement #20's judgement was never given, taken 2026-09-10** by doing the split and reverting it: 9 items move (`answer_transfer`, `abandon_transfer`, `send_transfer_error`, `transfer_error`, `answer_update`, `zone_context`, `update_reply`, `UpdateFailure`, `apply_update_to_file`), 411 code lines; `main.rs` non-test code 1692 → 1300, net +19 for the `use` block. **Seven of the nine seal** — the compiler named exactly two, `answer_transfer` and `answer_update`, both called from the root's two dispatchers. Content-preserving: diffed against `HEAD` with the two `pub(super)` markers stripped, zero substantive lines; `cargo test -p rdnsd` 118 before and 118 after, clippy clean (Windows). So the code side of #20's objection comes out in favour, its criterion — an owner and a lifetime — still does not: the module reaches into 6 of `Server`'s 8 fields. ~~**The two that cannot seal are #39's**, which is the prerequisite: with one dispatcher instead of two, all nine seal.~~ **39b landed 2026-09-10**, and the split followed it the same day. `rdnsd/src/dispatch.rs` — "one request in, its reply on the wire" — took the whole contiguous run from the `Handler` impl to `notify_reply`: `main.rs` 1691 non-test code lines before 39b and **1016** now, against `dispatch.rs`'s 629. **Two doors and fifteen items sealed**, where the trial measured two doors and seven: `Wire` and `Server::answer` are `pub(super)`, and `finish`, `error_bytes`, `truncated_reply`, `notify_reply` and `Wire`'s two methods became module-private alongside the nine the trial named — the dispatcher moving with the cluster is what took them. Two tests travelled with their code (#20's rule), the OPT-mirroring one and the NOTIFY one, and no test was lost: 907 on Windows, 923 on Linux, unchanged. `cargo doc` earned its place again, catching a `[`UpdateHandling`]` link that the move left pointing at nothing. The test coupling #20 named is real and unchanged by the move — the tests need not travel, and if they do, 10 of `main.rs`'s 64 and 5 helpers shared with tests that stay |
| ~~**38e**~~ | ~~the fixtures cannot be shared, so they are written three times~~ **mostly done 2026-09-10; the cross-crate half is decided against** | ~~`test_records` is `#[cfg(test)]`, so `tests/` and `benches/` — separate crates — cannot see it: `query_message` is identical in `benches/answer_path.rs:53`, `tests/allocations.rs` and `tests/no_input_panics.rs`, and `zone_at` in `ixfr.rs` and `journal.rs` in a module that already imports `test_records::nm`. A `testkit` feature gating those modules, or a dev-dependency crate, is the usual answer.~~ Counting first turned up a bigger instance than the one filed: the scratch-directory helper was written **seven times in `rdns`** and once more in `rdnsd`, and three of those removed the directory on the last line of the test body — the line a failing assertion skips — rather than in `Drop`. One per crate now (`rdns::testutil`, `rdnsd::testutil`, `rdns-transport::testutil`), plus `test_records::zone_at`. **The cross-crate half is not done and should not be**: a `testkit` feature is on for every build whose features unify with the tests’, so the fixtures compile into the shipped binaries to spare `tests/`, `benches/` and `examples/` about twenty lines of `nm` and `query_message`. `test_records::nm`’s own doc had already reached that conclusion for `nm`. If it is ever taken up it gets its own number. ~~Beside it: `rdns-transport`, the admission path both daemons’ packets pass through, has **3 tests** for 627 lines~~ — **11 now**: `tcp.rs` had none at all, and the eight are the writer task’s two guarantees, the drain, the abort, the zero-length prefix, the idle timeout, #17’s framing wrap and #30e’s per-connection rate |

**What the review checked and found nothing wrong with**, so the next one need
not: a whole-tree scan for repeated function bodies (≥6 lines, normalised) found
**two** in 61k lines, both test fixtures; every `.lock().unwrap()` (21) is in a
test; non-test `#[allow]` attributes number 2; `Cargo.toml`'s dependency
comments still match what the code imports.

---

### 21. The deviations and the not-implemented list — decisions, not open work

**Filed 2026-08-03**, after the architecture review's findings were closed and
`docs/spec/` was committed. Every *gap* that review found (G-1 to G-5) is fixed;
what is left in the spec are four **deviations** — places the code and an RFC
disagree on purpose — and a list of things simply not implemented. None of them
was in this file, which meant the only record that they had been *decided* rather
than overlooked lived in a document nobody reads before starting work.

**This section is not a queue.** It exists so the next person to notice one of
these finds the decision instead of re-deriving it, which is the same job
`CLAUDE.md` §16's "what the pass checked and found nothing wrong with" does. If
one of these is ever taken up it gets its own number.

#### The four live deviations

| | what | decided |
|---|---|---|
| ~~**D-1**~~ | ~~a label that is not valid UTF-8 is refused, where RFC 2181 §11 allows any binary string~~ | **Fixed 2026-09-07 by #36**, which took the argument in the last clause below. The reasoning that produced the deviation is left standing, because it is why the deviation existed: ~~**Deliberate, and the one with a real cost.** Names are `String`s in presentation form throughout; the alternative is a different representation (labels, or wire bytes), which is what **#13e** scopes — its map-key half is done and its `Name` half is *deferred*, not declined, and #11 owns the storage question. The consequence is easy to under-read: a zone containing such a name cannot be served, *and* a response containing one is unparseable, so `rdnsr` cannot relay someone else's zone that has one. **That last clause is the strongest argument anywhere on this page for taking #13e's `Name` half**, and it is not among the reasons #13e was deferred — those were about allocation counts and churn.~~ (Not #15, which is a different question: that was the `DName`/`UnpackedDName` typestate collapse, withdrawn on its own merits, and it would not have changed what a label may contain.) |
| **D-5** | RFC 1035 §2.3.1's LDH "preferred name syntax" is not enforced | **Deliberate, and enforcing it would be a bug.** RFC 2181 §11 settles it; enforcing LDH would refuse `_dmarc`, every `_tcp` SRV owner, DNS-SD instance names and the wildcard `*`. #15 records that a `TODO` asking for this was deleted rather than done, because doing it was the defect |
| **D-6** | the first compression pointer in a chain may point forward | **Deliberate.** Every *subsequent* pointer must strictly decrease, which is what makes cycles unreachable without a visited-set; the first is unconstrained because a name is parsed from a suffix slice that does not know its own offset. Termination is unaffected, and the reasoning and the cost of the alternative are written at `dname.rs` |
| **D-7** | class CH and HS are refused rather than served | **Deliberate.** RFC 1034 §4.3.2 step 1 searches the zones *of the question's class*, and holding none in a class is the same situation as holding no zone. The visible cost is that `version.bind CH TXT` — which BIND, NSD and Knot all answer — is not answered here. Serving it would mean a second class in the zone index, which #13d's class-blind index deliberately made unrepresentable |

#### Not implemented

Scope, not defects. Listed so "is this missing on purpose?" has an answer.

| | note |
|---|---|
| DoT / DoH / DoQ (7858 / 8484 / 9250) | each is a transport, and each drags in a TLS stack — the dependency argument §14 makes about the OTLP exporter applies with more force here |
| SIG(0) (RFC 2931) | TSIG covers the transaction-authentication case this server actually has. SIG(0) matters for a client that cannot share a secret in advance, which is not a deployment this serves |
| DNS Cookies (RFC 7873) | round-trips as an opaque EDNS option. Implementing it properly is a second anti-spoofing mechanism beside the response budget, and the budget is the one that is there |
| `$GENERATE` | a BIND zone-file extension, not an RFC. Absent because nothing here needed it |
| white lies / minimally-covering NSEC (RFC 4470) | the denial chain is precomputed at signing time, so a lie would have to be signed online. That is a different signing model, not a feature |
| key-rollover *automation* (RFC 6781) | rollover is manual and the signer will not delete a published DNSKEY, which is the half that matters: a key published without its private half is how every rollover starts, and deleting it would undo the operator's preparation |

~~**One of these is a stronger candidate than the rest**, and saying which is the
point of writing the list down: **DNAME**, because it is the only entry that
makes this server give a *wrong* answer rather than an incomplete one — a name
under a DNAME gets NXDOMAIN or NODATA where an implementation that followed it
would synthesize a CNAME.~~ **Taken 2026-09-06 and done — #34.** The paragraph is
kept because it is why the work happened, and because it is the only time this
list has been used for what it was written for: a session with no queue read it,
found the argument already made, and did that.

Everything else on the list is something absent that announces its own absence,
which is why none of the rest is marked. ~~The next strongest, on the same
reasoning, is **SVCB/HTTPS**: an operator who writes one in a zone file has to
hand-encode it in `\#` form, and a mistake there is silent.~~ **Taken 2026-09-07
and done — #35.** Twice now this list has been read by a session with no queue
and used to pick the work, which is what it is for; nothing on it is marked any
more.

---

## Closed work

One line each. The reasoning, the RFC citations and the verification are in the
commit that closed it and in `docs/CLOSED_WORK.md`, which holds every section
below in full under the same number — ~~every one~~ **all but two as of
2026-09-11**: #38's and #39's sections are closed and still sit under "Open
work" above, which is the same drift the second correction under this table
records, caught this time with the row rather than after it. **The numbers are stable identifiers** —
referenced from 88 doc comments in the tree and from each other — so they are
moved, never renumbered.

**Read this table, not a summary of it.** Eight times by its own count, a
sentence at the top of this page has said what was open and been wrong within
the week; the record is under "How the queue kept going stale" in
`docs/CLOSED_WORK.md`.

| # | what it was | outcome |
|---|---|---|
| **1** | recursor follow-ups | done |
| **2** | DNSSEC follow-ups | done |
| **3** | NSEC3 salt and iterations | done |
| **4** | zone lookup | done |
| **5** | smaller items: AXFR, TSIG, NOTIFY, IXFR, amplification, negative caching, `$INCLUDE`, TXT framing | done. No section of its own; the entries are in `docs/CLOSED_WORK.md`'s "Done so far" |
| **6** | special-use names in `rdnsr` | done |
| **7** | the secondary role, in six steps | **all six done 2026-08-03.** Step 6, persisted deltas, waited on #10 and landed with it: `rdns/src/journal.rs` |
| **8** | what signing turned up — the re-signing timer and its serial | done. Settled by reading BIND, Knot, PowerDNS and NSD, which converge on something better than either option written down |
| **9** | what a five-way review found: 48 defects in six groups (9a-9f) | **all done 2026-07-27 → 2026-08-01.** No section: the patterns became `CLAUDE.md`, which is the useful artefact, and the 2,435 lines of finding text are in `git log -p TODO.md` |
| **10** | dynamic UPDATE (RFC 2136) | **done 2026-08-03**, seven commits. Incremental re-signing and the journal closed it |
| **11** | data layout and CPU cache friendliness | **answered no, 2026-08-04.** Measured with cachegrind: all L2-resident, zero LL misses either way. There is no pointer chase to remove, and the `perf` blocker it carried for months did not exist |
| **12** | pre-authentication panics | **audited 2026-08-01.** No reachable panic in 1.4M mutated inputs; two mutex-poisoning fixes; `rdns/tests/no_input_panics.rs` left behind as the guard |
| **13** | making illegal states unrepresentable | **done 2026-08-02**, twelve commits, seven live defects fixed on the way. ~~13e's `Name` half deferred with a reason~~ — **closed as #36 on 2026-09-07**, and the row stayed wrong for two days. The deferral's reasons were allocation counts and churn; neither survived contact with it, since not one of `allocations.rs`'s forty-four assertion ranges moved |
| **14** | `Serial`, QR as a type, sealing `RecordData` | **all three done 2026-08-02**, one commit each. 14c found that a legal RFC 2136 UPDATE could not be parsed at all |
| **15** | collapsing `DName`/`UnpackedDName` | **withdrawn 2026-08-03**, reviewed against the code rather than the plan. Keeps the three findings and two fixes the review did produce |
| **16** | simplifications: `Nsec3`'s fallibility, splitting `parse_into`, a duplication that must stay | **16b done, 16a corrected-and-withdrawn, 16c recorded as not-to-fix, 2026-08-02.** 16a's filed plan did not survive contact with `nsec3_hash`; the pass it came from found a live defect in `proves_no_ds` |
| **17** | the TCP length prefix wraps to 0 on a TSIG-signed answer near 64 KB | **fixed 2026-08-03.** The one confirmed bug of that review — provoked, not argued |
| **18** | `rdnsr` has none of the operational shell | **fixed 2026-08-03.** Seven library facilities wired into one daemon and not the other, the more amplifying one |
| **19** | the 2026-08-03 review's smaller items, 19a-19h | **closed 2026-08-03.** Five stragglers of consolidations that caught most copies and missed one |
| **20** | `rdnsd/src/main.rs` is one file and eleven subsystems | **done 2026-08-03**, one commit per seam. 8,328 → 5,956 lines, every move diffed against `HEAD` to prove it changed nothing |
| **22** | the zone lookup is hash-bound | **closed 2026-09-05.** One map instead of two takes a miss from 1,875 to 1,402 instructions. The second direction is a decision and the answer is **no** — the threat model is in the section |
| **23** | `NsecCache::synthesize` hashes once per cached NSEC3 record, under one mutex | **fixed 2026-08-04** (`9715c3c`), the day after filing. 1 124 ms → 1.28 ms on the same probe |
| **24** | three costs that grow with something the operator chose | **all three fixed 2026-08-05.** Zone selection 55 µs → 32 ns and flat at ten thousand zones; name compression O(n²) → linear in one message's records; an AXFR at 10.5× less peak memory |
| **25** | per-answer waste on paths #9e already measured | **closed 2026-09-04**, eight items. Two of the eight had corrected themselves on the way and the section says so |
| **26** | helpers written twice, and hand-rolls with a standard spelling | **closed 2026-09-04**, ten items. 26a/26c/26d turned out to be eight copies rather than six — the two nobody found carried none of the names the others did |
| **27** | what a zero-allocation answer path would take | **closed 2026-09-05**, five of six stages done and 27d withdrawn. A query cost 21 allocations when it was filed and costs **2**, both in the parse; nothing on the answering side allocates at all |
| **28** | work the answer path does and need not | **28a-28c done and 28d answered no, 2026-09-01.** Six clock reads per query cost 144-155 ns and four wanted the same instant |
| **29** | the resolver half never got #27's pass | **filed and closed 2026-09-04**, five commits |
| **30** | the two daemons' transports are one transport written twice | **closed 2026-09-05.** Eighteen lettered items — the filing said seventeen and 30r was found while doing 30g; 30q was the one defect (`rdnsr` never ran the admission check on TCP) and 30k is recorded as not-to-fix. The rest landed once `rdns-transport` existed. ~~Its row here read **open** until 2026-09-05~~ — see the correction below |
| **31** | where a crate boundary would pay | **done 2026-09-05.** `rdns-transport` holds #30's transport; `rdns-core` holds the wire format, which takes a client from 67 packages to 35. Two crates, not the three the plan drew |
| **32** | `Shell`, `Served` and the other unnamed bags | **closed 2026-09-05.** The prediction held: naming the five was the extraction, and `ServeContext` landed in the same commit as the pipeline it parameterizes |
| **33** | a fourth pass: duplication, generics, and where the modules are cut | **closed 2026-09-06**, eight items over two days. 33b was the one defect in a shipped binary — `rdnsc` could not ask an ANY or AXFR query, because the builder took an RTYPE. Five further candidates were dropped and the section says why |
| **35** | SVCB and HTTPS (RFC 9460) | **filed and closed 2026-09-07**, one commit — the wire format and the presentation format are joined by an exhaustive match, so they could not be split. RFC 9460 Appendix D's eight wire vectors are a test, and Figure 10 caught a real design error: the value format is picked by how the key is *spelled*, not by its number. Brought RFC 1035 §5.1's escapes into the tree for the first time, which found a quoted escape in a name being silently mis-parsed — a defect with nothing to do with SVCB — and retired the `\DDD` limitation that made binary TXT go out in generic form |
| **36** | #13e's `Name` half: names as wire octets | **filed and closed 2026-09-07**, two commits — the type on its own, then the whole tree onto it, because `ResourceRecord::name` and `QuerySection::qname` are used by every crate and the field type could not change in stages. Closes **D-1**: a label is any binary string now, and a response carrying one relays byte for byte. Five defects found on the way, none of them in the mechanical part, and the oldest is that a name inside RDATA was never resolved against the origin (RFC 1035 §5.1) — `www IN CNAME host` stored `host.`. Of the rest: the delegation and DNSKEY caches inserted a folded key and looked one up unfolded, the NSEC3 closest-encloser walk went through presentation text once per candidate name, and `to_wire` sized every unpacked name at 255 octets and then shrank it. `dname.rs` lost its presentation half in the same commit — both directions, and a second text-to-wire decoder that disagreed with `Name` about RFC 1035 §5.1's escapes. Not one of `allocations.rs`'s forty-four assertion ranges moved; dnspython validates twenty-one answers off a signed zone, including a name with a `.` inside a label |
| **34** | DNAME (RFC 6672) | **filed and closed 2026-09-06**, five commits — the record type, the zone, the server algorithm, the resolver, then signing and UPDATE. Taken off #21's not-implemented list, which had named it the only entry there that answered *wrong* rather than incomplete. Two bugs found by the new tests: a `Zone` flag maintained in one of the two places that maintain its siblings (now one `Shortcuts` value), and DNAME missing from UPDATE's singleton list. One test had to be rewritten because it passed with the guard it was named for deleted |
| **37** | where a module folder pays, and where it is motion | **filed and closed 2026-09-08**, four items. 37a was the defect: `utils::label_count` splits presentation text on `.` and `NameRef::label_count` counts wire labels, so an owner holding RFC 1035 §5.1's `\.` — loadable and signable since #35 and #36 — read as one label more in text than on the wire, and `rdnsr --dnssec` SERVFAILed a name `rdnsd` serves correctly. 37b, 37c and 37d were splits, and each corrected the count in its own row: a flat split widens only what crosses a file boundary (7 of 19, not 19), Rust privacy runs downward so a child reading its parent widens nothing (19 of 29, not 29), and `rdns-core`'s fifth module was dropped because moving two private functions to a sibling *widens* them. The measurement for a split is visibility, not line count, which is #33's rule and the reason a `dnssec/` directory stayed dropped |
| **38** | a structural review, and what it left | **filed and closed 2026-09-09 → 2026-09-10**: three fixes in the filing commits and five sub-items after them, 38e's cross-crate half decided against rather than done. **Nothing filed was a defect**; the one defect the review turned up was in the fixed half — a DO bit dropped by three reply paths across both daemons, against `rdnsd/src/answer.rs`, which mirrored it. 38d's `rdnsd` half is what filed #39. **Section still above rather than in `docs/CLOSED_WORK.md`** |
| **39** | `rdnsd` answers through two dispatchers | **filed and closed 2026-09-10 → 2026-09-11**, five items. 39a was the defect: a TSIG-rejected request counted as received over TCP and not over UDP, because the two prologues had drifted. 39b built all three shapes before keeping one, and the two it declined are the argument — a trait that had to name the type it existed to hide, and a `transport` plus `out` pair that could disagree with itself. **Section still above rather than in `docs/CLOSED_WORK.md`** |

**Two corrections this rewrite had to make**, recorded rather than quietly
applied (`CLAUDE.md` §11):

- **#30's row said `open` while its own "Order" section said every remaining
  item was done.** Both were written on the same page within a day of each
  other. A status held in two places disagrees eventually, which is the argument
  for this table being the only place a status lives.
- **Fourteen section headings were wrong or absent.** Eleven still said
  "filed" for work that had closed (#7, #22, #24-#32) and three carried no
  status at all (#2, #14, #16). All fourteen are corrected in
  `docs/CLOSED_WORK.md` with the original struck through, because a heading is
  the first thing read and was the last thing updated.

---

## Architecture: the resolver

One `Resolver` type with `ResolverMode::{Recurse, Forward}`, chosen by config —
not two programs. That is how BIND, Unbound, Knot Resolver and PowerDNS Recursor
all model it, and for the same reasons: the client-facing half is identical, only
the means of obtaining an answer differs, and mixed deployments (forward one
zone, recurse the rest) need both in one process. `rdnsr` recurses by default;
any `--upstream` selects forwarding.

**Recursion** walks root hints → TLD → authoritative, following referrals. The
built-in hints carry both an A and an AAAA for each of the 13 roots, interleaved
so whichever family the host has is reached early; `query_server` binds its send
socket to the target's family (a v4-wildcard socket cannot reach a v6 address),
which is what makes AAAA glue usable at all. `parse_root_hints` loads the
`named.root` format for `rdnsr --root-hints`. Three controls are load-bearing:

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

**Reply validation** guards every response `query_server` accepts: the
transaction id must match, and the echoed question must be the name we sent.
With **0x20 case randomization** on (`zero_x20`, default on) the outgoing name's
letter case is scrambled and the question check is case-sensitive, so an off-path
spoofer has to reproduce the casing on top of the id and the random source port;
off, the check is the ordinary case-insensitive one. A mismatch is treated as no
answer, so `ask_any` moves to the next server. Turn 0x20 off for the rare
authoritative server or middlebox that does not preserve case.

**QNAME minimization (RFC 9156)** is on by default (`qname_minimization`, off to
send the full name every hop). Each hop asks the current servers only for the
next label down toward the target — `com.`, then `example.com.`, then the leaf —
so the root learns the TLD and no more, and the full name reaches only the
server authoritative for it. Intermediate probes use QTYPE=NS: a zone cut answers
with a referral, a plain in-zone name with NODATA, telling the two apart without
disclosing the leaf. An empty non-terminal (a name with descendants but no
records of its own) returns NODATA to the NS probe, so the walk deepens by a
label and re-asks the same servers rather than mistaking it for a final answer;
that costs one extra probe per such label. NXDOMAIN on an ancestor ends the walk
— the whole subtree is empty (RFC 8020). Bailiwick is still judged against the
full target name, so minimizing the query does not widen what a referral may
claim.

**The delegation cache** (`DelegationCache`) keeps the servers learned per zone,
keyed by zone name with the referral's shortest TTL, capped at a day. A
resolution starts at the deepest cached ancestor of the name rather than at the
root: knowing `example.com.` beats knowing `com.` because it skips a round trip.
A cached delegation that fails is dropped and the walk restarts from the root, so
stale bookkeeping degrades to slow rather than broken. `delegation_cache_size`
(10k default, 0 disables). Verified: three queries into one zone consult the root
exactly once.

**Server selection** within a zone is fastest-first, not round-robin or
learned-order. `RttStore` keeps a smoothed round-trip time per server address
(EWMA, α=0.25, the RFC 6298 SRTT factor); `ask_any` orders the candidates by it,
times each round trip, and charges a failure the full timeout so a dead server
sinks to the back after one attempt. Unmeasured servers sort at a middling
default (`UNKNOWN_RTT_MS`), so a fresh set is tried in the order given, a
measured-fast server beats an untried one, and an untried one beats a known-bad
one. The store shares the delegation cache's capacity, evicting the slowest
entry when full; a resolution keeps preferring the fast server and only re-tries
a demoted one once the fast one also fails (no active re-probing yet).

**Forwarding** sends RD=1 to each configured upstream and returns the first
answer, going through the same `ask_any` (so upstreams are RTT-ordered too).
Recursion sends RD=0 — an authoritative server has no business recursing for us,
and asking it to is how open resolvers get abused.

Tests (36 in `resolver.rs`) stand up a fake root/TLD/authoritative hierarchy
in-process. They share one port across distinct loopback addresses, because glue
carries an address and no port — which is also why `server_port` exists in the
config.

## Architecture: DNSSEC

Four modules, split by what they know rather than by record type:

| module | what it answers |
|--------|-----------------|
| `dnssec` | do these bytes verify under this key; does this DNSKEY hash to this DS |
| `dnssec_denial` | does this NSEC/NSEC3 actually deny the thing being claimed |
| `dnssec_chain` | trust anchors, and the verdict for one step of the chain |
| `resolver` | fetching, ordering, caching — the async half |

`dnssec_chain` is deliberately synchronous and takes records as arguments;
fetching them means asking servers, which is the resolver's job. The resolver
drives the loop and calls in at each step. That split is what makes the chain
logic testable without a socket.

**The load-bearing function is `dnssec::signed_data`.** A signature is not over
the RRset as it arrived; it is over `RRSIG_RDATA(signature field removed) ||
canonical RRset` (RFC 4035 §5.3.2), where canonical means the RRSIG's *original*
TTL rather than the received one, owner names down-cased, a wildcard-expanded
owner replaced by the wildcard that was really signed, embedded names down-cased
for the RFC 4034 §6.2 types, and the records sorted by canonical RDATA with
duplicates dropped. Sorting is by RDATA **alone**, not by the encoded RR: RDLEN
sits between the fixed prefix and the RDATA, so sorting whole records orders by
length first and puts a short RDATA ahead of a longer one that precedes it.

**Four states, and the two that matter are Insecure and Bogus.** Insecure means
the chain legitimately ended — a zone *proved* it has no DS — and is the normal
case for most of the internet; the answer is served without AD. Bogus means the
chain was supposed to continue and did not, and the answer is withheld. Conflate
them and you either break the unsigned internet or launder attacks. Indeterminate
is a third thing again: no trust anchor covers the name, so there was never a
chain to walk.

**DS is collected during the walk, not asked for afterwards.** A referral is the
only moment the *parent's* side of a zone cut is in front of us. Querying the
child for its own DS lets the child answer a question about itself; querying the
parent again costs a round trip already spent. So `walk` reads each referral's
authority section into `Resolution::cuts` as it goes past, and validation
consumes what the walk collected. This is also why the delegation-cache shortcut
is narrowed when validating: skipping ahead to a cached zone also skips the cut
above it, so `best_start` only jumps to a zone whose keys are already validated —
and `establish_chain` resumes at exactly the same place, or the two disagree and
an answer that validated a moment ago comes back bogus.

**A stripped DS must be bogus, not insecure.** Delete the DS records from a
referral and a naive validator concludes "unsigned zone, nothing to check",
downgrading every signed zone beneath it. So the absence of a DS is only
believed when the parent *proves* it with a signed NSEC/NSEC3 — and the proof is
verified as an RRset like any other, because an attacker can write NSEC records
too. Opt-out (RFC 5155 §6) is the one case where a merely *covering* NSEC3
suffices, and only with the flag actually set.

**A wildcard answer is not finished when its signature verifies.** A wildcard is
signed at `*.example.com.`, and the labels field in the RRSIG says so — which
means the same RRset and signature verify at *every* name that wildcard could
expand to. Re-own a genuine `*.example.com. A` RRset onto any name under
`example.com.` and the cryptography still checks out. So a verified expansion
carries an obligation out of `validate_records` (as `RecordsVerdict::wildcards`)
and `validate_wildcard_proofs` discharges it against a signed NSEC/NSEC3, which
must show two things: the name asked about has no records of its own, and the
wildcard used is the one its *closest encloser* publishes. The second half is
the one that is easy to miss — `b.example.com.`'s own NSEC covers
`a.b.example.com.`, because a name sorts before everything beneath it, so
"some NSEC covers the name" would accept a `*.example.com.` answer for a name
that `b.example.com.` governs. For NSEC that is checked by deriving the closest
encloser from the covering record; NSEC3 gets it for free, since the name it has
to cover — the next closer — is named from where the wildcard sits (RFC 5155
§8.8). An Opt-Out NSEC3 there yields Insecure rather than Bogus: it declines to
say whether a delegation is in the span, which is not a proof and not an attack.

**And the same thing on the negative side.** A NODATA answer usually rests on the
NSEC *at* the name, whose bitmap lists the types it has. But the name may not
exist at all, a wildcard may be what answered, and it may have had no record of
this type either — so the proof is a different pair: the name shown absent, and
the record at the wildcard showing what a wildcard would have carried (RFC 4035
§5.4, RFC 5155 §8.7). Demanding only the first shape refuses a legitimate answer,
which is what `proves_nodata` did: any zone with a wildcard got SERVFAIL for
every type the wildcard does not hold. The depth check matters here for the same
reason as on the positive side — `*.example.com.`'s bitmap says nothing about a
name that `b.example.com.` governs.

Two things that fall out of this and are worth not re-deriving. A record sitting
*at* a wildcard is not an expansion of it — the labels field never counts the
leading `*` (RFC 4034 §3.1.3), so the arithmetic alone flags the wildcard's own
RRset, and demanding a proof that `*.example.com.` does not exist would break
every wildcard-aware denial, since those carry exactly that record.
`is_wildcard_expansion` therefore compares against the name that was signed.
And the proof may arrive with an *earlier* hop of a CNAME chase, whose authority
section does not survive into the message we return, so `Resolution` accumulates
NSEC/NSEC3 records across hops the same way it accumulates zone cuts.

**A verified answer is not yet a coherent one.** Every RRset in an answer may
carry a good signature from the zone that owns it and the collection still not be
an answer to the question asked: a genuine `a.example.com. CNAME b.example.net.`
beside a genuine `something-else.example.net. A 6.6.6.6` is two authentic RRsets
and no chain, and a client reading "the A record in the answer" has been handed an
address for a name nobody asked about. `dnssec_chain::cname_chain_shape` walks the
answer from the question, follows each CNAME to its target, and requires every
record present to be either a link on that walk or an RRset of the queried type at
the name it ends on. Bounded, loop-detecting, case-insensitive, and it stops before
the first hop when the question *was* for a CNAME (RFC 1034 §3.6.2).

The resolver's own `chain` filter already drops off-path records hop by hop while
it fetches, which is why this rarely has anything to reject during recursion — and
is also why it is hard to exercise end to end there. It earns its keep on an answer
that arrived whole: from a forwarder, which does no such filtering. It is checked
by unit tests over the shapes, plus a signed CNAME chain resolved end to end to be
sure a coherent answer is still accepted.

**The key cache stores conclusions, not material.** `KeyCache` holds DNSKEY sets
that have already been validated to an anchor, so a second query into a zone
costs no revalidation. That makes its TTL load-bearing, hence the one-day cap.

Failure is closed: `rdnsr` answers SERVFAIL on bogus, and never caches an answer
as validated that was not. A client setting CD gets the data unfiltered
(RFC 4035 §3.2.2) — it has said it validates for itself. AD goes out only for a
Secure answer and only to a client that set DO or AD (RFC 6840 §5.8), and a
client that did not set DO gets no DNSSEC records at all (RFC 4035 §3.2.1).

**Algorithms:** ECDSA P-256/P-384 (13/14), RSA/SHA-256 and SHA-512 (8/10),
Ed25519 (15), and RSA/SHA-1 (5/7) because a long tail of zones still uses it.
Anything else — RSAMD5, DSA, GOST, Ed448 — is *unsupported*, which per RFC 4035
§5.2 makes the delegation insecure rather than bogus: we have no basis to call an
answer forged when we simply cannot read the signature.

**Testing.** Port 53 is intercepted here (see "Verifying"), so there is no live
signed zone to point at — which is precisely how this code came to be written
without a genuine signature ever reaching it. `dnssec_test_util` generates real
keys with `ring` and signs at test time; `resolver.rs` stands up a signed
root → `test.` → `example.test.` hierarchy in-process and drives the whole
resolve path through it, including the substituted-answer, unvouched-key,
stripped-DS and proven-unsigned cases.

## Architecture: aggressive use of validated denials (RFC 8198)

An NSEC record does not say "this name does not exist". It says "nothing exists
between these two names", and it is signed. A validator holding one therefore
already knows the answer for *every* name in that gap, and asking the
authoritative server again learns nothing it was not already told. `NsecCache`
caches the gap rather than the question, which turns a flood of random names
under one zone — a water-torture attack, or an ordinary typo storm — from one
upstream query per name into one query per zone.

This could not be bolted onto `DnsCache`. That maps `(name, type)` to records
and can only answer the question it was asked; a gap has to be searched by
*range*. So the proofs live in a `BTreeMap` ordered by
`dnssec_denial::canonical_sort_key` — a byte encoding of the labels right to
left, each terminated by a zero byte, whose plain `Ord` is exactly RFC 4034
§6.1 canonical order. A covering lookup is then `range(..=key).next_back()`,
falling back to the last entry for the record that wraps to the apex.

Everything here is a way of *not* asking, so every mistake is invisible until it
denies a name that exists. Five rules keep that from happening:

- **Only Secure material is stored.** `rdnsr` inserts a denial only when
  validation returned Secure. An unvalidated NSEC is an attacker's assertion
  about which names do not exist, which is a denial-of-service primitive.
- **Never across an opt-out NSEC3 span** (RFC 8198 §5.2). Opt-out means the span
  may contain delegations the zone never named. Refused at *insert* rather than
  at lookup, so no code path can consult one.
- **Never below a delegation.** This one is not in the RFC's list and is the
  easiest to get wrong. A gap says nothing exists *in this zone* between its
  endpoints; if its lower edge is a delegation (NS set, SOA clear), everything
  under that name lives in the child zone — and those names sort *inside* the
  gap, because `sub.example.com.` and `x.sub.example.com.` are canonically
  adjacent. Synthesizing there denies an entire zone we were never authoritative
  for. `ZoneProofs::covering_nsec` refuses it, and a test pins the ordering fact
  that makes it possible.
- **NXDOMAIN needs the wildcard denied too**, or a name the gap covers could
  still have been answered by a wildcard higher up. Rather than re-derive that
  argument, the cache gathers the candidate records and hands them to the same
  `dnssec_denial::proves_nxdomain` that validated them — a second implementation
  would drift from the first.
- **TTL is bounded by the proof**, not by the question: the minimum of the
  proof records' remaining life and the SOA's negative TTL (RFC 2308 §5),
  applied in one place to every record going out, so a client cannot re-cache a
  proof for longer than we may hold it.

At a delegation point the parent holds only the DS, so a NODATA there is
synthesized for QTYPE=DS and refused for anything else — the real answer to
those is a referral. ANY and RRSIG are never synthesized: neither can be
reasoned about from a type bitmap.

**The positive half, §5.3.** A validated *wildcard* answer is the same kind of
statement as a validated NSEC — one signature covering a whole set of names — so
it is kept too, under the wildcard rather than under the name that happened to be
asked for. Another name the wildcard reaches is then answered without asking,
with the records re-owned onto it and the wildcard's own signature attached: that
signature verifies at the new name unchanged, which is exactly what makes this
legal and also why a wildcard answer needs its own denial in the first place.

Two rules, and the second is where this would go wrong:

- **The name must be proved absent**, by a cached covering NSEC. An existing name
  shadows the wildcard entirely (RFC 1034 §4.3.3), so without that proof there is
  no basis to answer at all — and the same delegation rule applies as on the
  negative side, for the same reason.
- **The wildcard must be the one that governs the name**: `*.` plus its *immediate
  parent*, and nothing shallower. A wildcard reaches exactly one label (RFC 4592
  §2.1.1), and "some cached NSEC covers the name" cannot tell `a.example.com.`
  from `a.b.example.com.`, because a name sorts before everything beneath it. The
  wildcard is therefore *derived* from the queried name rather than searched for
  among the ones we hold, which makes the mistake unavailable.

  **The citation here is wrong — see #9a.** RFC 4592 §2.1.1 is about zone-file
  syntax, not synthesis depth; the source of synthesis is the wildcard immediately
  below the *closest encloser*, which can be several labels above the queried name
  (§3.3.2). The *conclusion* still holds for this cache, and for a sharper reason
  than the one given: we may only synthesize where we hold a proof, and deriving
  the wildcard from the queried name is what keeps a shallower wildcard from being
  applied to a name a deeper existing node governs.

  **Re-checked against #9a's fix, 2026-07-28, and the rule stands** — the comments
  in `nsec_cache.rs` now say so in the correct terms rather than by citing §2.1.1.
  The two sides *do* disagree, as predicted: `rdnsd` synthesizes at the closest
  encloser, `rdnsr` considers only the immediate parent, so the resolver declines
  to synthesize some answers the authoritative server would have given. That is a
  **cache miss and a real query**, not a wrong answer, and it is the only safe
  direction available: deciding the closest encloser needs to know which
  intermediate names *exist*, and a covering NSEC cannot establish that — a name
  sorts before everything beneath it, so `b.example.com.`'s NSEC covers
  `a.b.example.com.` whether or not `b` is there. Widening it needs cached proofs
  about the intermediate names, which is a piece of work nobody has scheduled and
  which buys only cache hits.

The two halves cannot both fire: a cached NXDOMAIN requires the wildcard to have
been *denied*, so it never applies to a name a wildcard governs.

`rdnsr` checks the denial cache *before* the answer cache, and skips it entirely
for a client with CD set — that client asked us not to filter on its behalf, and
an answer we invented from cached proofs is exactly that. The cache is sized to
zero unless `--dnssec-validate` is on, the same zero-capacity idiom `--no-cache`
uses, so there is no configuration in which unvalidated proofs can enter it.

## Architecture: what `rdnsr` remembers

Three caches, because there are three shapes of thing to remember and one map
cannot hold them:

| cache | key | holds |
|-------|-----|-------|
| `DnsCache` | (name, type) | the records that answered |
| `NegativeCache` | name, or (name, type) | that there were none (RFC 2308) |
| `NsecCache` | a *range* of names | a signed statement that none of them exist (RFC 8198) |

`NegativeCache` is not redundant with `NsecCache`. The denial cache holds
validated material only — everything it does rests on the proof having been
checked — so it is sized to zero unless `--dnssec-validate` is on, which for most
deployments means negative answers were not cached at all and every repeat of a
failing lookup was a fresh walk to the authoritative server.

The two kinds of "no" are keyed differently because they say different things.
**NXDOMAIN** is about the name: no type at it exists, and nothing below it does
either, since a name with descendants would be an empty non-terminal answering
NODATA (RFC 8020 — the resolver's walk already stops on an ancestor's NXDOMAIN,
and a cache that disagreed with the walk would be the odd one out). The lookup is
therefore a walk up the ancestors, bounded by the label count. **NODATA** is about
one type at a name that does exist, so it is keyed by both and says nothing about
any other type.

Three rules keep it honest. **An SOA is required** — RFC 2308 §5 takes the
negative TTL from it, so a "no" that arrives without one never said how long it
was good for; this is also what keeps a referral out of the cache. **The TTL is
`min(SOA MINIMUM, the SOA record's TTL)`, capped at an hour**, and the records
handed back count down, so a client cannot re-cache a "no" for longer than we may
hold it. **Nothing bogus is stored**, and whether an answer validated is stored
with it, so the AD bit the second client sees is the one the first client saw.

Lookup order in `handle_query` is denials → negatives → answers → resolve. The
denial cache goes first because it answers questions never asked, and is skipped
for a client with CD set for the same reason. The negative cache is not skipped:
it returns the answer *this* question actually got, which is caching rather than
filtering.

`rdnsd` had to change for any of this to work: a negative answer now carries the
zone's SOA in the authority section (RFC 2308 §2.1, §2.2). Without it a
downstream resolver — ours included — has no negative TTL and cannot cache the
answer at all.

## Architecture: persistence

Settled before writing any of #7, because every step below depends on it: **plain
files, no database**, with the format chosen per kind of state.

| state | store | why |
|-------|-------|-----|
| fetched zone data | a text **zone file**, written by us | the format already parsed and tested here; inspectable; what NSD and BIND do |
| per-zone transfer state | a small **line-based text file** (`zone serial last-refresh master`) | keeps operational state out of the interchange format — BIND leans on the file's mtime instead and pays in imprecision |
| IXFR deltas | **in memory**, derived by diffing at load time | zones come from files and reload in discrete events; NSD answered AXFR instead of deltas as a primary for years |
| RFC 5011 anchors | a **writable trust-anchor file** | Unbound's `auto-trust-anchor-file:` model; `TrustAnchors::parse`/`from_file` already exist |

Four rules, and the first is why step 1 of #7 exists at all:

- **One writer per file.** Which means one process: two `rdnsd`s over the same zone
  cannot both own writable state.
- **Write a temporary file, then rename.** `std::fs::rename` replaces an existing
  file on both Unix and Windows, so this is portable; the fsync-the-directory
  refinement is POSIX-only.
- **Nothing on the query path touches disk.** Memory stays authoritative for
  answering — the zone index is 0.685 µs a lookup and must stay that way. Disk
  exists to survive a restart, nothing else.
- **Missing or corrupt state degrades, never crashes.** No state file means "never
  refreshed", which means fetch. The same posture the caches already take: when in
  doubt, go and ask.

**Why not SQL or LMDB.** PowerDNS is database-backed because in its deployments the
*source of truth* is a provisioning system's database; here it is a zone file. SQL
would add a C dependency and a schema-migration story to persist a few kilobytes,
buy nothing on the hot path (the in-memory index stays either way, so the database
is an expensive file), and cost the dependency-light character of the rest of this
codebase. LMDB is Knot's choice and right *at Knot's scale* — journals, catalog
zones, key state, hundreds of thousands of zones; this serves single digits. Three
triggers would change the answer: thousands of zones, dynamic UPDATE at a real
write rate, or an external system owning the data.

**What the others actually persist**, since it is the evidence for the table above:
NSD keeps `xfrd.state` for serials and transfer times and rewrites secondary zones
into their zone files hourly; BIND keeps a per-zone `.jnl` journal (dynamic UPDATE,
IXFR both ways, inline signing) plus managed-key files for RFC 5011; Knot puts
journal, timers and key state in LMDB. And the surprise: **neither BIND nor Unbound
persists its resolver cache** — `dumpdb`/`dump_cache` are inspection tools, and
Unbound's only real answer is the optional Redis-backed `cachedb` module. Knot
Resolver is the outlier that does (LMDB on disk). So `rdnsr` losing its cache on
restart is mainstream rather than a gap, and is the one store on this page not to
build.

## Architecture: names that never leave (RFC 6761, 6762, 6303)

Some names are reserved for uses that are not the global DNS, and treating them as
ordinary questions does three things wrong at once: it answers slowly (a full walk
to the root, then a failure), it answers wrongly (whatever a wildcard-happy TLD or
a captive portal decides to say), and it *tells the root servers* what those names
are. The reverse lookups leak most: every query for `10.in-addr.arpa` describes a
piece of somebody's internal addressing to a public server, and AS112 exists purely
to absorb the flood of them.

`special_names::lookup` is a table consulted **first** — before every cache, before
any resolution. For these names the table *is* the answer, so consulting anything
else would already mean a query going out.

- **`localhost` and everything under it** is the loopback address (RFC 6761 §6.3).
  The subtree matters: `api.dev.localhost` is as much this machine as `localhost`
  is, and software relies on it. Types other than A and AAAA get NODATA, not
  NXDOMAIN — the name exists, and saying otherwise would be a lie about the one
  name every machine has.
- **`.local` is mDNS** (RFC 6762 §3), so NXDOMAIN is the literal truth rather than
  a policy: the name really does not exist in the DNS.
- **`invalid.`** is reserved to be unresolvable (§6.4).
- **The private reverse zones** (RFC 6303 §4), including `127.in-addr.arpa` with
  `1.0.0.127` answering `localhost.`, and the sixteen separate zones that 172.16/12
  actually is — `in-addr.arpa` splits on octet boundaries and that block does not.

**Not in the table, deliberately:** RFC 6761 also reserves `example.`,
`example.com.`, `.net` and `.org` — as *ordinary* names, delegated and resolvable.
Special-casing them would break the only thing they exist for, which is being
copied out of documentation and working.

Two properties worth stating. **Never AD**, because nothing here was validated — it
was decided by specification, and claiming otherwise is the one lie a validating
client cannot check for itself. And **not skipped for a client with CD**: CD says
"do not withhold an answer because it failed validation", which is about DNSSEC, not
a request to hear what a public server thinks `localhost` is.

Each negative answer carries a **synthetic SOA** so a downstream resolver can cache
it (RFC 2308 §5 takes the negative TTL from it). It has to be invented — these
zones exist by specification rather than by delegation — and follows what Unbound
synthesizes for a `local-zone`, with `nobody.invalid.` as the responsible mailbox:
unmistakably synthetic, and guaranteed by §6.4 not to resolve.

**Verified live** by forwarding to `192.0.2.1` (TEST-NET-1, which cannot answer):
every special name was answered anyway, none with AD, while `example.com` and
`1.1.1.1.in-addr.arpa` went to the network — visible in their 0x20 case-randomized
echo, which only comes back from a real server.

## Architecture: following a trust anchor (RFC 5011)

A trust anchor is a key you decided to believe out of band, so every change to one
is an out-of-band event: a rebuild, or an operator editing a file. That holds until
the key rolls — and the root KSK does roll, at which point every validator that
has not been updated fails closed on the entire internet. RFC 5011 makes the roll
followable, using the zone's own signed DNSKEY RRset as the announcement channel.

`--auto-trust-anchor <file>` turns it on. The difference from `--trust-anchor` is
who owns the file: that one is read and never written, this one is read *and*
rewritten as keys move.

**Two rules carry the whole security argument.**

- **A new key is trusted because it stayed, not because it appeared.** Thirty days
  of continuous publication (`ADD_HOLD_DOWN`) before adoption. The point is the
  time: an attacker who has the zone's keys must keep the compromise up, and
  visible, for a month before any validator adopts a key of theirs.
- **A key is revoked only by itself.** REVOKE counts only when the RRset carrying
  it is signed *by that key* (§2.1). Without that, whoever holds any one of a
  zone's keys could retire the others. `self_signers` verifies each candidate
  *alone* against the RRSIGs, so "someone signed this" can never be mistaken for
  "this key signed this".

**Everything rests on the input having been validated**, and `observe` cannot check
that for itself — it is handed a DNSKEY RRset and reasons about it over time.
`probe_zone` therefore insists on `Secure` and nothing else: an Insecure or
Indeterminate answer for a zone we anchor is not an unsigned zone, it is an answer
that could not be tied to the anchor. Same posture as `NsecCache::insert_validated`,
and the same warning in the docs.

Four things that are easy to get wrong, three of which were:

- **Identity is (algorithm, protocol, public key), not the record.** Revoking sets
  a flag and therefore changes the key tag (§2.1 says so explicitly). Identifying
  keys by tag or RDATA makes a revocation look like an unrelated new key — and
  starts a hold-down on the key being retired.
- **The hold-down must not restart when the key is observed again**, or it never
  elapses and the key is never adopted. A failure that would surface 30 days after
  a roll, in production. There is a test that probes daily for a month.
- **A revocation outranks a configured DS.** The operator wrote "trust this
  digest"; the key has since said, with its own signature, to stop. Leaving the DS
  in place would mean a static anchor can never be retired by the mechanism built
  to retire it — and the built-in ICANN anchor is exactly such a DS. So a tracked
  key is kept in its *unrevoked* form (a DS digest covers the flags, so only that
  form matches) and the revocation lives in the state.
- **Only secure entry points are tracked.** The literal reading of §4 tracks every
  key in the RRset; against the real root that means tracking the ZSK, which nobody
  will ever publish a DS for. The root replaces its ZSK quarterly by dropping it,
  never by revoking it, and a key that merely disappears stays trusted by design —
  so the literal reading gains a permanently trusted stale key every three months.
  SEP is formally a hint, so this narrowing would miss a zone that rolled to a KSK
  without it; that is an unusual mistake with `--trust-anchor` as the way out,
  whereas unbounded growth of the trusted set is invisible.

**A key that merely vanishes stays trusted** (`Missing`). Deliberate: a key
disappearing is far likelier to be a zone publishing badly than an operator
retiring one, and retiring has a mechanism. **And with no anchor for a zone,
nothing is learned about it** (§5) — a resolver that bootstrapped itself there
would be trusting whatever answered.

**Persistence** is the writable trust-anchor file the persistence table called for,
in Unbound's spirit: DS and DNSKEY lines in presentation format, with `;;state=`
and `;;since=` annotations carrying the bookkeeping. A DNSKEY line *without*
annotations is read as a key the operator has decided to trust outright, because
making them write bookkeeping fields by hand to be believed would be a trap. The
file is written at startup if absent, so pointing at a new path shows immediately
what is trusted rather than after the first change. Unlike the transfer sidecar, a
corrupt file here is **fatal**: forgetting a serial costs a refresh, forgetting
anchor state costs either the internet or a hold-down that had nearly elapsed.

The live anchor set is behind `SharedAnchors` (a `std::sync::RwLock`, cloned per
validated resolve so no guard is ever held across an await), because the point is
to follow a roll without a restart. The set is replaced only *after* the file is
written: validating against keys we could not record would forget them on restart,
which is what the file exists to prevent.

**Verified against the real root zone**, which was not expected to be possible
here — port 53 is intercepted (see "Verifying") and recursion generally fails, but
a one-hop `./DNSKEY` query does get answered. So the probe ran for real: key 20326
was adopted immediately as the built-in DS's match, and the two other published
keys entered hold-down. That run is what found the ZSK-tracking flaw above — no
unit test would have, because the flaw is in what the real root publishes. The
state machine's timing, and the revocation rule against genuine signatures
(`dnssec_test_util` keys that really sign), are covered by tests.

## Architecture: incremental transfer (RFC 1995)

An AXFR moves the whole zone whenever any part of it moves: a serial bump and one
changed address cost a fresh copy. That is what makes a secondary with a short
REFRESH expensive to be, and what IXFR exists to fix.

**Where the deltas come from was the decision.** BIND keeps an on-disk journal,
which is what you need when the zone is edited in place by dynamic UPDATE —
there, the journal *is* the record of what happened. Here a zone comes from a file
and changes in discrete events (a reload, or a transfer from a master), so the
difference between two versions can be computed when the new one arrives and kept
in memory. That is `ixfr-from-differences` without the journal, and the same call
NSD made. A journal earns its keep at #7 step 6 and not before.

**The consequence, stated so nobody is surprised:** a restart forgets the deltas.
Every secondary asking for an increment across one gets a full transfer instead,
which RFC 1995 §4 permits unconditionally and which corrects itself at the next
change. `DeltaLog` also keeps only `MAX_DELTAS_PER_ZONE` (32) steps per zone; a
client further behind than that gets the zone.

**The response is positional, and that is the part to get right.** Not "the
changed records": the current SOA, then one *difference sequence* per version step
— old SOA, deletions, new SOA, additions — then the current SOA again. A client
reads the second record of the stream to decide what it is holding; another SOA
means an increment, anything else means the server fell back to the whole zone.
Four things make it fall back, each logged: no SOA in the request, no unbroken
chain back to the client's serial, a chain that does not reach the serial we are
serving, or an increment no smaller than the zone (§4 says to send the zone then,
since the point is that less crosses the wire).

**A gap in the chain is not something to paper over.** If the steps from the
client's serial do not link end to end up to the current one, applying the rest
would leave the client holding a zone that never existed — with a serial saying it
is current, which no comparison afterwards could catch. `chain_from` returns
nothing rather than a partial chain, and the answer is a full transfer.

Three details worth not re-deriving:

- **The apex SOA is excluded from the deltas.** It is carried by the framing, as
  the header of each half; a copy among the records would read as the start of
  another difference sequence.
- **A TTL change is a deletion and an addition.** A secondary caches and re-serves
  that number, so two records differing only in TTL are not the same record to it.
  This is what BIND produces too.
- **The diff counts rather than sets.** A zone holding the same record twice does
  not read as a change when one copy is removed.

**The delta log is derived state, so it moves with the zone map or not at all.**
Every replacement goes through `install_zone`/`install_all_zones`, which take both
locks and record the step in the same call — the same hazard the zone index has,
and the reason `note_change` wants both versions rather than being something a
caller can forget. A zone that is withdrawn (expired, or gone from the
configuration) has its history dropped: offering increments of a zone we no longer
serve would be answering for something we stopped serving. Under `answer_transfer`
the log is read *under the zone lock*, so the increments and the zone they are
increments of are the same version.

**Gated by the same ACL as an AXFR**, because an IXFR may answer with the whole
zone — a policy that let it through would be no policy at all.

**Over UDP, the answer is always a single SOA of the current version**, which is
RFC 1995 §2's own "come back over TCP" signal. Deliberate rather than a
limitation: the ACL, the TSIG session and the multi-message packing all live on
the TCP path, and duplicating them to serve the increments that happen to fit a
datagram would be a second implementation of the interesting parts.

### The client half

A refresh asks for the difference whenever it has a version to differ from, and
for the whole zone when it does not. That is a *preference*, not a demand — which
is why there is one code path and not two.

**The answer's shape is positional, and a client cannot assume it got what it
asked for.** The signal is the second record of the stream: another SOA means
difference sequences follow, anything else means the server chose to send the
whole zone. A client that assumed sequences would read a zone's first ordinary
record as the header of a delete section and start deleting things. `IxfrAssembler`
therefore switches to `AxfrAssembler` at that point rather than growing a second
copy of the rules about what a transfer may contain — bailiwick, the closing SOA,
the bound — which apply identically either way.

Two boundaries in that state machine are worth not re-deriving. An SOA arriving
during a sequence's *additions* is either the next sequence's header or the
closing record, and the serial is what tells them apart: the next sequence starts
where this one ended, which equals the current serial only when there is nothing
left to send. And an "already current" answer is a single SOA with no terminator
of its own, so it is recognised by being the whole of the first message — a server
with sequences to send packs them into that same message rather than sending one
record and pausing.

**Applying is rebuild, not edit** (`ixfr::apply_changes`), which is the
simplification noted under #7 and the reason `Zone` has no record-removal API and
should never get one: the index holds *positions* into the record vector, so
removing in place invalidates every later one. Rebuilding is O(zone size) per
sequence rather than per record, and the result is a zone built by the ordinary
constructor whose index cannot disagree with its contents.

**A deletion for a record we do not hold is counted, not fatal.** It means our
copy and the master's had already diverged — worth logging, never worth refusing
the transfer over, since the record is meant to be gone either way and failing
would strand the secondary on a version it can never leave.

One consequence worth knowing: an increment and a full transfer produce the same
zone but not the same *file*, because a changed record is deleted and re-added and
so moves to the end of the load order. Confirmed identical as record sets, which
is what a zone is; a textual diff between two secondaries that took different
routes to the same serial is expected.

**Verified live, both directions.** Outbound, against dnspython — our client and
our server agreeing about a format proves nothing. A secondary holding one
recorded change was asked for an increment by `dns.query.inbound_xfr` from serial
200; dnspython applied it and arrived at serial 201 with exactly the right nine
records. The other two paths too: asking from the current serial changed nothing
(one SOA), and asking from a serial we never held replaced the client's zone
wholesale and dropped a record that only existed there.

Inbound, as a three-node tree — primary → S1 → S2, which is also the check that
this composes. The primary was restarted with a changed zone, so it had no deltas
and sent S1 the whole zone (`sent in full`, exactly as documented). S1 recorded the
step, and S2's next refresh took it as `1 incremental step(s)`: 8 records on the
wire against the 12 a full transfer moved, with the changed address updated, the
new record present, the deleted one answering NXDOMAIN, and the untouched records
untouched. S1's and S2's zones compared identical as record sets.

## Architecture: the secondary role

Two modules, split by whether they touch the network. `xfr` is the client half of
a transfer — asking for a zone and deciding what of the answer to believe.
`secondary` is the policy: when a refresh is due, when a zone has gone stale, and
what survives a restart. The timing rules have no I/O in them and all the
interesting edge cases, so they are tested by moving a clock rather than by
waiting.

**What `xfr` refuses is the interesting part**, because a stream that was merely
*received* is not a zone:

- **It must open and close with the apex SOA** (RFC 5936 §2.2). The closing SOA is
  the only thing distinguishing a complete transfer from a cut connection, and a
  secondary that swapped in a truncated zone would answer NXDOMAIN for everything
  the stream did not reach — worse than not updating at all.
- **Every record must be in bailiwick.** A master for `example.com.` sending a
  record for anything outside it is writing into a name it is not authoritative
  for. Same rule as the resolver's, same reason.
- **The stream is bounded** (`MAX_TRANSFER_RECORDS`), because a master that never
  sends the closing SOA is otherwise a slow way to exhaust memory.
- **AA must be set**, and the rcode must be NOERROR. AA is how the master says the
  zone is its to hand out.

TSIG is chained across envelopes: the first is verified against the request's MAC
and each one after against its predecessor (RFC 8945 §5.3.1), so a dropped or
reordered envelope fails at the client rather than passing for a complete zone.
An envelope with *no* TSIG when a key is configured is refused rather than
accepted — §5.3.1 permits omitting intermediate signatures, and handling that
properly means feeding the unsigned bytes into the next signed envelope's digest,
which `check_response` has no way to express. Refusing is the honest position
until it does; the note is here so the next person does not conclude the chaining
is simply wrong.

**The cycle** is RFC 1035 §4.3.5's, per (zone, master): ask for the SOA, compare
serials with RFC 1982 arithmetic, transfer if behind, sleep on REFRESH — or on
RETRY if anything failed, with a NOTIFY cutting the wait short. Reaching the
master resets the staleness clock whether or not anything was transferred: a zone
confirmed unchanged is exactly as current as one just fetched.

**EXPIRE is the timer with teeth, and the only place a secondary is required to
make things worse for its clients.** Out of contact past it, the zone stops being
served. The alternative is worse: a zone served with AA set is a claim to be
current, and a server that keeps making that claim turns a primary's outage into
permanently wrong answers that nobody can see are wrong. Withdrawn, the query gets
REFUSED, which sends a resolver to the other nameservers in the delegation.

Three details that are easy to get wrong and were:

- **Expiry is measured from the last time the master answered**, not from the last
  time the zone changed. A zone that has not changed in a year is not stale.
- **Expiry has to survive a restart**, or it lasts only as long as the process:
  the stale file is loaded from disk and served again, authoritative once more.
  So the state line is *kept* when a zone expires — it is the record of when
  contact was last made — and `expire_stale_zones_at_startup` consults it before
  anything is served. Deleting the line would read as "never fetched", which means
  "fetch", which means serving the stale copy.
- **A zone we have never reached counts its EXPIRE from process start.** Not
  "forever ago", which would withdraw a zone before ever trying, and not "never",
  which would serve a copy of unknown age indefinitely because we happened to
  restart.

REFRESH and RETRY are clamped to a 60-second floor. The RFCs set none because they
did not imagine one being needed; a zone whose SOA says `refresh 0` is otherwise a
loop that asks its master as fast as the network allows. EXPIRE is *not* clamped —
it is a limit on staleness, and raising a small one would serve a zone longer than
its operator said to.

**A NOTIFY now has three answers**, where it used to have one. From a master of a
zone we replicate: NOERROR, and the refresh happens now. From anywhere else for
such a zone: REFUSED — a policy decision, the same shape as the transfer ACL's,
because a NOTIFY is a spoofable datagram that costs its recipient a transfer. For
anything else: NOTAUTH, which is the truth for a zone we hold as a primary and one
we have never heard of alike. The serial inside the message is deliberately not
acted on: it is unauthenticated, and the refresh does its own comparison against
what the master answers.

**Persistence** is what "Architecture: persistence" settled: the zone as a text
zone file written by `zone_writer`, under its origin's name, so the ordinary load
path reads it back with nothing to distinguish it from one an operator wrote; and
a line-based sidecar (`rdnsd.state`) holding `zone serial refreshed-at master`.
Both are replaced atomically. The sidecar never fails a load — a missing or
corrupt one means "nothing fetched", which means fetch, and refusing to start over
a scratch file would make it a single point of failure.

**Verified live, two `rdnsd` processes**, with dnspython as the client throughout:

- a fresh secondary transferred the zone, served it, and wrote it down;
- changing the primary's zone and restarting it produced `NOTIFY … acknowledged
  (Ok)` on one side and `refreshing now` → `transferred serial 101 -> 102` on the
  other, with a record deleted on the primary gone from the secondary;
- the secondary restarted with the primary *down* and served the zone from its own
  written file — the step-2 writer and the zone parser closing the loop;
- a zone with `EXPIRE 60` whose master was killed logged
  `EXPIRE (60s) passed with no contact — no longer serving this zone` and answered
  REFUSED thereafter.

That run is also what caught the two bugs under `docs/CLOSED_WORK.md`'s
"Done so far" that no unit test
would have: the validator dropping NOTIFY before anything read its opcode, and the
refresh loop reading the zone's timers *before* the transfer that installs them,
so the first refresh after a first fetch waited the default hour instead of the
zone's own REFRESH. Both look perfectly correct in a test that only asserts the
transfer happened.

## Architecture: signing a zone

Three modules, split by what they know. `dnssec_key` holds private keys and can
make a signature; `zone_signer` turns a zone into a signed zone; `dnssec_answer`
decides which of those records a particular reply needs. None of them validates
anything — `dnssec` and `dnssec_denial` were written first and are what the tests
here judge the output with, which is the point: a signer checked against a
validator written alongside it proves the two agree, not that either is right.
The independent check is **dnspython**, which validated every RRset `rdnsd`
served under both chains.

**Keys are PKCS#8 in a file of our own, and the extension says so.** BIND's
`.private` format differs per algorithm and keeps the public half in a second
file; `ring` will take none of it, wanting PKCS#8 with the public key alongside
the private one. Converting between the two is a format conversion whose failure
mode is a key that signs with the wrong identity, so it is not attempted: the
file is `Owner`, `Flags`, `Algorithm` and base64 PKCS#8, named
`K<zone>+<alg>+<tag>.rdnskey`, and `openssl genpkey` output imports as-is. The
owner name and flags live *in* the file rather than at the call site, because the
key tag is computed over the flags — a key whose flags were decided by the loader
would have a different tag depending on who loaded it, and every RRSIG naming
that tag would point at a key nobody can find.

Signing algorithms are deliberately a subset of what verification accepts. A
validator has to read whatever the internet was signed with; a signer chooses,
and RFC 8624 §3.1 is the list of what may be chosen. RSA/SHA-1 is therefore
verifiable here and not signable. RSA at all is import-only, because `ring`
implements RSA signing and not RSA key generation.

**What is not signed is the part worth getting right.** A zone's authority stops
at a delegation: the NS RRset pointing down carries no signature, the glue below
it is not in the zone at all, and the only signed thing at a delegation point is
the DS — plus the denial record, which exists precisely so the *absence* of a DS
can be proved. Signing a delegation's NS is the classic signer bug; every
validator ignores the signature, and the stray RRSIG then shows up in that name's
NSEC bitmap as a type that is not there.

**Empty non-terminals are in the chain, and this is the subtle one.** A name with
no records of its own but with descendants still *exists*, so a query for it is
NODATA — and the proof of a NODATA has to be a record *at* the name. Left out of
the chain, the only record available would be one saying the name does not exist,
which is a different answer with a signature on it. RFC 5155 §7.1 says so
outright for NSEC3; for NSEC it follows from what NODATA means, and it is why an
NSEC zone walk enumerates names that hold nothing.

**Signing is in memory, at load, and the zone file is never rewritten.** The file
on disk stays the unsigned thing an operator edits. A signer that rewrote its
input would have to solve the same "who owns this file" problem the transfer
sidecar stepped around (see "Architecture: persistence"), an editor and a
resigning timer racing for one file is a way to lose a zone, and nothing needs
the file anyway — what a client validates is what leaves the socket. Only zones
read from disk are signed: a zone that arrived by transfer is the master's,
signatures included, and the parent's DS points at their key.

**A signed zone is not a signed answer**, which is what `dnssec_answer` is for.
Three of the four shapes owe a *proof* rather than a signature, and each missing
one is a specific attack:

| the answer | what it owes | why |
|------------|--------------|-----|
| ordinary positive | the covering RRSIGs | — |
| from a wildcard | the RRSIGs, re-owned onto the queried name, **and** a denial that the queried name exists | one wildcard answer verifies at every name that wildcard reaches (RFC 4035 §3.1.3); without the denial, capturing one is capturing all of them |
| NODATA | a record at the name whose bitmap lacks the type | — |
| NXDOMAIN | a denial of the name **and** of the wildcard that could have answered it | otherwise a wildcard-covered name can be denied |

Re-owning a wildcard's RRSIG onto the queried name is not forgery and not a
special case: the label count in the RRSIG still says where the signature was
made, and that count is how a validator reconstructs the name that was really
signed. Changing the owner and leaving the count alone is the shape of a genuine
wildcard answer.

**Finding the covering record is a range query, so the zone holds two ordered
indexes.** `Zone` already indexed names in a `HashMap` for lookups; a denial asks
a different question — "which record's span contains this name" — which a hash
map cannot answer without looking at everything. So NSEC records are also filed in
a `BTreeMap` by canonical sort key and NSEC3 records by their hash, and the
covering record is the greatest entry strictly below the target, wrapping to the
last when nothing sorts below it, because the chain is a loop. Both are empty for
the unsigned zones that are most of them. Scanning instead would have put an
O(records) walk on the negative-answer path, which is the mistake the name index
exists to have already fixed.

The NSEC3 salt and iteration count are read off a record *in the chain* rather
than off NSEC3PARAM. NSEC3PARAM exists to tell a server which of several chains
to use mid-rollover, a notion this server does not have; parameters taken from
the chain cannot disagree with the chain, whereas an NSEC3PARAM left over from a
previous signing can, and the failure would be every denial hashing to something
no record matches.

**What we produce is checked before it is served.** `dnssec_validation_mode` —
which had no caller until now — is run over every zone at load: each signature in
the zone must cover an RRset that verifies against the zone's own keys. The
question is "does every signature hold", not "is everything signed", because a
delegation's NS and its glue carry none by design. `--require-signed` adds the
stronger assertion that every zone here is meant to be signed at all, and a
failure of either refuses to start rather than serving something a validator will
call bogus.

## Architecture: writing a zone back out

Two modules, and the split is the same one the persistence table makes: `persist`
knows how to replace a file safely and nothing about DNS; `zone_writer` knows how
to spell a zone and nothing about disks.

**`persist::write_atomically`** writes a temporary sibling, `sync_all`s it, and
renames it over the target. The sibling matters — a rename across filesystems is
a copy, which is the non-atomic thing being avoided — and so does the fsync
*order*: without it a crash can leave the directory entry pointing at a file
whose blocks were never written, so "the rename happened" would not imply "the
contents are there". The temporary carries the pid, because "one writer per file"
is a rule about the target and a leftover from a crashed process must not be
something a later run renames into place. Syncing the directory afterwards is
POSIX-only and best-effort: it is a durability refinement, not a correctness one,
since no reader can observe a partial file either way.

**`zone_writer` has one rule: what is written must read back as the same bytes.**
Not the same *meaning* — the same bytes. A fetched zone may be signed, and a
signature covers RDATA octet for octet, so a record re-spelled in a way that
re-encodes even slightly differently becomes bogus at a validating client rather
than failing here. Every line is therefore rendered type-specifically only when
that provably round-trips, and otherwise in RFC 3597 §5's generic
`\# <len> <hex>` form, which is exact by construction.

The check for "provably" is one comparison, not a list of cases: parse the stored
RDATA, re-encode it, and see whether the bytes come back identical. That catches
RDATA carrying trailing bytes its type does not define, a name whose labels do
not survive a round trip, and anything else of that shape without this module
having to anticipate it. **One gap is not visible to it and is worth not
re-deriving:** a type bitmap is stored and re-encoded verbatim, so a bitmap
padded with trailing zero bytes passes that check intact — and then the *text*
form silently drops the padding, because a list of type names says which types
are set and nothing about how they were laid out. So NSEC and NSEC3 additionally
compare the bitmap against the one the parser would rebuild, and go out generic
if it differs.

Everything else about the format follows from making a line independent of its
neighbours: owner names absolute, a TTL and class on every record, so nothing
depends on directive order or on which record happens to precede which.
`$ORIGIN` and `$TTL` are still emitted for other tools, and because an origin is
worth recording in the file rather than left implied by the file's *name*.
Records keep their load order under the apex SOA, which leads the file — so
rewriting an unchanged zone produces an unchanged file, and a diff between two
versions shows what actually moved.

**The one thing that cannot fall back is an owner name**: it is the first field
of the line, not RDATA, and this parser has no escape syntax for a label holding
a dot or a space (the gap listed under #5). Such a name is refused, and the write
fails, rather than producing a file that reads back as a different zone.

Two things landed on the *load* path to make this work, both RFC 3597 §5.
`TYPEnnn` is accepted and emitted wherever a type is named, so a type this
library has no parser for is expressible — in a record and in an NSEC bitmap
alike. And a type bitmap listing a name with no type code is now an error rather
than a silent omission: dropping one turns an NSEC that denies six types into one
that denies five, which is a signed record quietly changed into a different
signed record.

**Verified against dnspython**, which is the check that matters here — our parser
agreeing with our writer proves nothing. A zone with SOA/NS/DS/DNSKEY/RRSIG/NSEC/
NSEC3 and a generic `TYPE1234` was written by `zone_writer` and read by
dnspython, and every record's `to_digestable()` matched our stored RDATA byte for
byte. Also confirmed idempotent: writing the output again reproduces it exactly.

## Architecture: zone storage

Records live in one vector; an index built as they are added maps the absolute,
down-cased owner name to the positions of the records at it. `origin` and
`records` are private because the index is derived from both — a record appended
behind its back, or an origin changed without a rebuild, leaves the zone
answering NXDOMAIN for data it holds, which is a bug this repo has already had
once. `$ORIGIN` mid-file therefore goes through `set_origin`, which re-keys what
is already loaded, keeping the result identical to resolving every relative name
against the final origin (what the query-time normalization used to do).

**Keyed by name, not by (name, type)**, though the TODO item said the latter. A
server needs two questions answered and the second is what tells NXDOMAIN from
NODATA: "which records of this type sit at this name", and "does this name exist
at all". A (name, type) map answers the first and cannot answer the second
without probing 65535 types; the records at a single name are a handful, so
picking a type out of them costs nothing measurable. It is also how NSD and Knot
hold a zone — a node per name, carrying its RRsets.

**Owner names are resolved as they are parsed**, not stored relative, so
`ZoneRecord.name` is always absolute for a parsed zone. That is what makes
`$ORIGIN` apply to the lines below it (RFC 1035 §5.1) and what gives `$INCLUDE`'s
optional origin argument something to mean. `Zone::set_origin` still re-keys,
because a record added through the API may carry a relative name.

**Reading the file is two passes.** `logical_lines` turns physical lines into
logical ones first: comments stripped, quoted strings respected, and lines joined
while parentheses are open. Parentheses are not cosmetic — every real SOA is
written across five lines — and `;` inside a quoted string is data, which matters
because TXT records are mostly semicolons. `$INCLUDE` then recurses, with the
origin and default TTL copied in and nothing copied back (RFC 1035 §5.1 requires
exactly that for the origin), a depth cap to catch a file that includes itself,
and relative paths resolved next to the including file — which is why
`parse_zone_file_at` exists alongside `parse_zone_file`.

**Wildcards are a walk up the tree, not a scan** — and, until 2026-07-28, not one
lookup either. `Zone::name_kind` climbs to the *closest encloser*, the deepest
ancestor of the queried name that exists, and the only wildcard that may answer is
the one directly below it (RFC 4592 §3.3.1). Synthesis therefore reaches any depth
— §3.3.2's worked example answers `_telnet._tcp.host1.example.` from `*.example.`
— but stops at the first existing name, empty non-terminals included (§4.4), and
does not happen at all at or below a delegation (§2.2.1). It is consulted *only*
when the name itself has no records, because an existing name shadows the wildcard
entirely, including for types it does not carry (RFC 1034 §4.3.3, §2.2.1). The old
scan returned the exact and the wildcard records together, merging two owners'
data into one RRset; that was fixed as a side effect of having to decide the
question. The one-lookup version that replaced the scan was itself wrong — see
#9a, and note that the walk is O(labels) with O(1) lookups, so the closest
encloser costs no more than the single probe did on the hot path (an exact hit
still returns on the first `HashMap` lookup).

## Architecture: amplification

Two limiters, because there are two different quantities to bound and the second
one is what a reflection attack is measured in.

`RateLimiter` counts **queries** per client: 100 per 10 s, burst 20. That is a
fairness limit, and it is blind to amplification — a query is a query whether the
answer is 60 bytes or 4000, so a client staying inside it can still have the
server emit 25 KB/s at whatever address it claims to be.

`ResponseLimiter` counts **bytes going out** per client: `--response-rate`, 8 KiB/s
by default with a four-second burst. The burst is what keeps ordinary use out of
it — a page load is a dozen names at once — while the sustained rate is what an
attacker would need and cannot get.

Over budget, the response is **truncated rather than dropped**, one in every two
(the *slip* of BIND's Response Rate Limiting; RFC 5358 is the reflector problem
itself). A truncated reply carries no records and measured 42 bytes against the
44-byte query that asked for it, so it cannot amplify — and RFC 1035 §4.2.1 has a
real client retry over TCP, where the handshake proves the source address and the
budget stops applying. Dropping every over-budget response instead would leave a
legitimate client with nothing but a timeout and no hint that TCP would work;
answering every one of them would make the refusal itself the reflector.

The per-client table is **bounded** (10k addresses). A spoofed flood arrives from
every address there is, so unbounded tracking would be the next thing to exhaust;
past the bound the limiter stops growing and truncates instead, which is small,
still answerable over TCP, and no longer proportional to the number of forged
sources.

Measured on a zone with a 2.5 KB TXT RRset, one address, 5.5 s at 200 queries/s:
**32.7 KB/s** of responses with the budget off against **13.2 KB/s** with the
default — the 8 KB/s rate plus the 32 KB burst spread over the window, which is
the arithmetic working rather than a leak.

## Architecture: NOTIFY

A NOTIFY is not a query, and that is the whole of the difference. The opcode is 4
rather than 0, so a server dispatching on nothing but the question section answers
it as a lookup for the zone's SOA — a plausible reply to a message that asked
nothing. `rdnsd` dispatches on the opcode now: QUERY goes to the zone lookup,
NOTIFY is answered as a NOTIFY, and everything else (UPDATE, STATUS, the obsolete
IQUERY) gets NOTIMP instead of being treated as a lookup.

**Sending** is on zone load — startup, and SIGHUP where signals exist — for every
zone whose serial moved *forward*, compared against what was last announced.
Unchanged is not news; backwards is not either, since a secondary compares serials
and would ignore it. The comparison is RFC 1982 serial arithmetic, so a serial
wrapping past 2^32 still reads as an increment rather than as a rollback that would
silence the zone forever. The message carries the zone's SOA (RFC 1996 §3.7 makes
that optional) because it saves the secondary a question. Retries are bounded and
any rcode ends them: a secondary answering NOTAUTH has still received it. The
targets are exactly what `--also-notify` lists — not the zone's NS set, which BIND
derives and which would mean sending to whatever a zone happens to name.

Messages are built under the zone lock and sent outside it: an unanswered NOTIFY
takes seconds to retry, and holding the map that long would block a reload behind
the network.

**Sending also happens when a zone we replicate moves**, which is what makes a
replication *tree* work rather than just a star. §3.2's "master" is whoever serves
the zone to someone, and a secondary in the middle of a tree is one; without this,
only the moments a primary learns of a change (startup, SIGHUP) produce a NOTIFY,
so everything below the first level waits out a refresh timer. See "Architecture:
the secondary role".

**Receiving** has three answers now that this server can be a secondary — refresh,
REFUSED, or NOTAUTH depending on what the zone is to us. See `notify_reply` and
"Architecture: the secondary role"; the attempt is logged in every case, since a
NOTIFY from an unexpected source is worth seeing (RFC 1996 §3.10 has a secondary
log exactly that).

## Architecture: TSIG

A TSIG is not a record, it is a *pseudo*-record: appended as the last entry of the
additional section, covering the message it is attached to. Verifying one means
removing it again and hashing what is left — which is why `tsig.rs` works on bytes
rather than on a parsed `DnsMessage`. A re-serialized message is not necessarily
the same bytes (name compression is a choice), and the MAC is over the bytes that
were actually sent. `find_tsig` walks the wire format to locate the record,
`strip_tsig` reproduces the message as it was before signing (ARCOUNT one lower,
the signer's own id restored — a forwarder may have rewritten the one on the
wire), and `append_tsig` puts one on.

What the digest covers (RFC 8945 §4.3.3, §5.4.2):

```text
request:   message-without-TSIG || TSIG variables
response:  2-byte length || request MAC || message-without-TSIG || TSIG variables
envelope:  2-byte length || previous MAC || message-without-TSIG || timers only
```

The **request MAC in the response's digest** is the part that matters: it binds
the answer to the question, so a reply cannot be replayed as the reply to
something else. For a zone transfer the MACs **chain** — each envelope over the
previous one, and the messages after the first hash only the timers (§5.3.1) — so
a dropped or reordered envelope fails at the client instead of passing for a
complete zone.

**Three failures, and they say different things.** BADKEY: I do not know that key
name, or not with that algorithm — which is also the answer for an algorithm we do
not implement, since either way we cannot check what arrived, and it is what stops
a peer downgrading SHA-256 to SHA-1 by asking. BADSIG: I know the key and the MAC
does not match. BADTIME: the MAC *did* match but the clocks disagree by more than
the fudge. The first two go back unsigned (there is nothing to sign with, or no
reason to believe the sender holds the key); BADTIME is signed and carries this
server's time, so the peer can see which of the two clocks is wrong (§5.2.3).

**Checked before anything answers.** A server that answered the question first and
verified the signature afterwards would be answering questions for whoever asked.

**A truncated MAC is refused** (BADTRUNC) rather than accepted at half length:
that is a policy this server does not have, and the honest failure is better than
a shorter MAC than the operator thinks they configured.

Two deliberate limits. A TSIG that is not the *last* record is treated as no
signature at all, because it does not cover what follows it — accepting one would
be a way to append anything to a signed message. And nothing here signs *outgoing*
queries: `rdnsr` and `rdnsc` have no TSIG support, so the only client in the
workspace is the test suite.

## Architecture: zone transfer

`transfer::axfr_messages` turns a zone into the sequence of messages a transfer
is; who may ask is `security::TransferAcl`'s business, and the two are separate
on purpose — the shape of the answer has nothing to do with the policy, and the
policy is the part that must be impossible to get wrong by accident.

**The framing is the protocol.** A transfer opens with the zone's SOA and closes
with the same SOA (RFC 5936 §2.2). That is not decoration: without the closing
SOA a client cannot tell a complete transfer from a stream that was cut, so the
apex SOA is emitted exactly twice and skipped in the middle. Messages are packed
to a 16 KiB target using an estimate that ignores name compression — an estimate
that can only be too large is the safe direction, since the real limit is the
64 KiB length prefix. Every message repeats the question and stands on its own as
a well-formed authoritative answer (§2.2.1 permits omitting it after the first;
including it is simpler and equally legal). A serialization failure part-way
through abandons the whole transfer rather than sending a prefix of it.

**The ACL defaults to refusing everyone**, which is the opposite of how the rest
of a nameserver works and is the point: an ordinary query leaks one record, an
AXFR leaks the zone. Rules are addresses or CIDR prefixes; families do not mix, so
a v4-mapped v6 peer cannot reach a v4 rule; a malformed rule stops the server
rather than silently shortening the list. Every attempt is logged either way — a
refused transfer is a probe worth seeing, and an allowed one is a copy of the zone
leaving the building.

**Three refusals, three different rcodes.** Not on the list is REFUSED (a policy
decision). A name that is not a zone apex we serve is NOTAUTH — deliberately not
the enclosing-zone lookup an ordinary query does, or asking for
`www.example.com.` would transfer `example.com.`. A zone with no SOA is SERVFAIL,
because there is nothing to bracket the transfer with. Over UDP it is FORMERR: a
whole zone does not fit a datagram and the protocol has no way to say "there is
more", so the request is malformed rather than merely unwelcome.

The TCP server's `answer` returns a *list* of framed messages for this reason.
One task pushes them into the reply channel in order, so a transfer's messages
never reorder among themselves; another query's reply may land between them,
which is legal — a client demultiplexes on the transaction id.

## Architecture: one process per server

Both daemons serve UDP *and* TCP from a single process, and both bind before they
announce anything so a port conflict fails at startup instead of after one
transport is already up. Two loops are spawned and whichever fails first takes the
process down — a server quietly answering on one transport and not the other is
worse than one that stopped, because a client's TC=1 retry (RFC 1035 §4.2.1) or a
zone transfer would simply hang.

`rdnsd` reached this late. It ran one process per transport, which was harmless
only while zones were read-only: the moment anything writes state — a fetched zone,
a refresh timestamp — that state needs a single owner, and two servers over the same
zone file racing to write it is not a design to grow into (see "Architecture:
persistence"). The `udp` and `tcp` subcommands are gone rather than kept as no-ops:
a flag that is accepted and means nothing is worse documentation than an error.

Merging also fixed something that was wrong on its own terms: the rate limiter,
request validator, logger and metrics used to be **one set per transport**, so a
client had two query budgets and the metrics each saw half the traffic. They are one
`Server` now, shared by both loops. The response *byte* budget stays UDP-only, since
a TCP query has completed a handshake and there is nobody to reflect at.

**The two transports do not have the same concurrency shape, and the difference
is the work rather than the protocol.** TCP is a task per connection, because a
connection is long-lived, carries many queries and can hold a transfer open for
minutes. UDP on `rdnsd` is a fixed pool of `--udp-workers` tasks that share the
socket and answer **inline**: answering from an in-memory zone has two await
points in it — the zone-map read guard and `send_to` — and takes microseconds, so
a task per datagram was 1,536 bytes of overhead on a job smaller than the
overhead. What limits the pool also bounds it, which is the point: past the
workers, datagrams wait in the socket receive buffer and the kernel drops the
overflow, which for UDP is the correct back-pressure and is counted by the
operating system rather than by us.

`rdnsr`'s UDP loop looks like the old `rdnsd` one on purpose. A recursion is
several round trips to servers on the internet — seconds, nearly all of it
waiting — so a small pool would leave the resolver idle and slow at once. It
keeps the task per datagram and bounds *that* instead, with a
`--max-inflight-udp` permit taken before the packet is copied. The rule the two
share is only where the decision goes: nothing is allocated on behalf of a
datagram before something has decided to keep it.

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

`rdnsr` (`rdnsr/src/answer.rs`): query → EDNS sanity check (FORMERR / BADVERS) →
`DnsCache` lookup → miss resolves by awaiting `Resolver::resolve` (async; each
upstream round trip is an `await`, no blocking thread) →
cache-store by (name,type)+TTL → reply, echoing the client's txn id with RA set
and OPT mirrored only if the client used EDNS. Cache hits return in 0 ms against
~7 ms for a miss.

It serves UDP *and* TCP on one host:port — both loops are spawned and whichever
fails first takes the process down, so it never silently serves one transport.
Its UDP loop still spawns a task per datagram, unlike `rdnsd`'s, and is bounded
by `--max-inflight-udp` (default 1024) rather than replaced by a worker pool:
see "Architecture: one process per server" for why seconds of recursion want the
opposite shape from microseconds of zone lookup.
TCP is not optional for a resolver: when an answer overflows the client's
advertised UDP payload we reply TC=1, and RFC 1035 §4.2.1 has the client retry
over TCP. The transport reaches `handle_query` as a `Transport` enum whose only
job is picking the response size limit.

Two things `rdnsr` does *not* share with `rdnsd`: it doesn't run the
`RequestValidator`, and it has no zone storage. `--no-cache` is a zero-capacity
`DnsCache` (`put` is a no-op at 0) rather than an `Option`. `--dnssec-validate`
turns on the chain walk described under "Architecture: DNSSEC"; the cache
remembers each entry's validation state alongside it, so an answer served from
cache carries the same AD bit the first client saw and no other.

---

---

## Quick reference: the RecordData API

```rust
// stored form (compact, wire-format, uncompressed names)
pub struct RecordData { pub rtype: u16, pub rdata: Box<[u8]> }

RecordData::from_wire(rtype, rdata, &unpacker)? // ingest from the wire
record.parse()?                                 // -> ParsedRecord, on demand
RecordData::from_parsed(&ParsedRecord::A(addr))? // build a record

// TXT is a sequence of byte strings, not a string (RFC 1035 §3.3.14): each is
// length-prefixed on the wire, at most 255 bytes, and the encoder refuses both
// an empty sequence and an over-long string.
ParsedRecord::TXT(vec![b"v=spf1 -all".to_vec()])
record.rtype                                    // type code, direct field read
```

## Quick reference: names on the wire

`name` owns the type and both text doors; `dname` is the wire *reader* — the
label walk, the pointer resolution and the length limits — and nothing else since
#36. `compression` holds only the per-message offset table and the policy for
which RR types may have compressed names in their RDATA.

```rust
let name: Name = "www.example.com.".parse()?;   // presentation text in
name.as_ref().as_wire()                         // uncompressed octets out
Name::from_wire_in(bytes, &unpacker)?           // off a message, pointers followed

// One compressor per message being serialized; offsets are meaningless across
// messages. DnsMessage::to_bytes drives this for you — you only touch it
// directly if you write a new serializer.
let mut c = NameCompressor::new();
pos = c.write_name(name.as_ref(), buf, pos)?;        // literal, or a pointer
pos = c.write_rdata(rtype, &rdata, buf, pos)?;       // NS/CNAME/PTR/SOA/MX only
```

Canonical DNSSEC output must stay uncompressed — use `dnssec::signed_data`, which
is the live canonicalization and the one the validator agrees with. (This used to
point at `serialization::serialize_resource_record_canonical`, which was deleted
in #9e: it never sorted and never down-cased, so it produced neither RFC 4034
§6.2 canonical form nor the ordering its own doc comment promised.)

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

## Quick reference: the DNSSEC API

```rust
// Typed views. Each carries its owner name, because a key or a digest applied
// at the wrong name is the bug these exist to prevent.
Dnskey::from_record(&rr)   // -> Option<Dnskey>;  .key_tag(), .is_zone_key()
Rrsig::from_record(&rr)    // -> Option<Rrsig>;   .is_current(now), .is_wildcard_expansion()
Ds::from_record(&rr)       // -> Option<Ds>;      .matches_key(&dnskey)

// The bytes a signature actually covers (RFC 4035 §5.3.2).
dnssec::signed_data(&rrsig, owner, class, &rdatas)?

// The leaf validator. `zone` is the only zone allowed to have signed this.
let proof = dnssec::verify_rrset(
    &Rrset::new(owner, rtype, class, &rdatas), &rrsigs, &keys, zone, now);
// RrsetProof::{ Verified { wildcard, expires }, Unsigned, Bogus(why), Unsupported(why) }
//   Unsigned  != Bogus: no signature at all is normal, a failed one is not.
//   Unsupported: an algorithm we cannot read -> insecure, never bogus.

// Denial of existence. Names compare by canonical_name_cmp, NOT as strings.
dnssec_denial::nsec3_hash(name, salt, iterations)?   // capped at MAX_NSEC3_ITERATIONS
dnssec_denial::proves_no_ds(zone, &nsecs, &nsec3s)   // -> Denial::{Proved, NotProved(why)}
dnssec_denial::proves_nxdomain(qname, zone, &nsecs, &nsec3s)
// Handles both NODATA shapes: the NSEC at the name, and the wildcard case where
// the name does not exist and the record at `*.encloser` is what applies.
dnssec_denial::proves_nodata(qname, zone, qtype, &nsecs, &nsec3s)
// A wildcard answer's other half: does this name have nothing of its own, and is
// `wildcard` the one its closest encloser publishes? Three states — Opt-Out is
// neither a proof nor an attack.
dnssec_denial::proves_wildcard_expansion(owner, wildcard, &nsecs, &nsec3s)
// -> WildcardVerdict::{ Proved, Unjudgeable(why) /* insecure */, NotProved(why) }

// The chain, one step at a time. Fetching is the resolver's job, not this API's.
let v = ChainValidator::new(&anchors, now);
v.start(name)                                  // -> Option<(anchor zone, its DS)>
v.validate_dnskeys(zone, &records, &ds_set)?   // -> Vec<Dnskey>, or a ValidationState
v.validate_delegation(&evidence, parent, &parent_keys)  // -> DelegationVerdict
v.validate_records(&records, &keystore)        // -> RecordsVerdict
//   .state     -> ValidationState, about the signatures alone
//   .wildcards -> expansions still owing a denial of the name they were served
//                 at. A Secure state with a non-empty list is not yet an answer.
v.validate_wildcard_proofs(&verdict.wildcards, &authority_records, &keystore)

// End to end, from the resolver:
let (answer, state) = resolver.resolve_validated(&query).await?;
// ValidationState::{ Secure, Insecure, Bogus(why), Indeterminate(why) }
//   Secure       -> may set AD
//   Insecure     -> serve it, no AD (provably unsigned: most of the internet)
//   Bogus        -> SERVFAIL, and never cache
//   Indeterminate-> no anchor covers the name; we never looked
```

## Quick reference: signing a zone

```rust
// Keys. The owner name and flags are part of the key, not of the call.
let ksk = SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256,
                               "example.com.", DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP)?;
ksk.write_to_dir(Path::new("/etc/rdns/keys"))?;   // K<zone>+<alg>+<tag>.rdnskey
let keys = SigningKey::load_dir(Path::new("/etc/rdns/keys"))?;  // a bad file is an error
ksk.ds(2)?          // what the parent has to publish; 2 is SHA-256
ksk.dnskey()        // what the zone publishes
SigningKey::from_pkcs8(alg, owner, flags, &pkcs8)?  // an openssl key, imported

// Signing. The input zone is untouched; the result is a new one.
let policy = SigningPolicy::valid_for(now, 30 * 86_400)   // inception backdated an hour
    .with_chain(DenialChain::nsec3());                    // or DenialChain::Nsec
let signed = zone_signer::sign_zone(&zone, &keys, &policy)?;
// Idempotent where it matters: the previous run's RRSIG/NSEC/NSEC3/NSEC3PARAM are
// dropped first. DNSKEYs are NOT — a pre-published key is how a rollover starts.

// Serving. `zone` is signed; these say what a reply owes beyond the records.
let sigs = dnssec_answer::answer_signatures(&zone, qname, qtype);
sigs.records                 // RRSIGs, owned by the queried name
sigs.wildcard                // Some(..) -> the answer still owes a denial:
dnssec_answer::proof_of_absence(&zone, qname)
dnssec_answer::negative_proof(&zone, qname, name_exists)  // NODATA vs NXDOMAIN
dnssec_answer::is_signed(&zone)                           // nothing to add if not

// The zone's own ordered chains, for finding a covering record without scanning.
zone.nsec_covering(name)      // greatest entry strictly below, wrapping
zone.nsec3_covering(&hash)
zone.holds_name(name)         // exact — NOT name_exists, which honours wildcards
```

## Quick reference: answer shape

```rust
// Is this answer the CNAME chain the question asked for? Independent of the
// signatures — each RRset verifying says nothing about the collection.
match dnssec_chain::cname_chain_shape(&qname, qtype, &answers) {
    ChainShape::Intact { final_name } => {}
    ChainShape::Broken(why) => {}   // -> Bogus
}
```

## Quick reference: the denial cache

```rust
// Zero zones disables it entirely — the same idiom --no-cache uses.
let denials = NsecCache::new(1000);

// Store a denial. ONLY for an answer that validated as Secure: nothing here
// re-checks a signature, so the caller's validation is the whole basis for
// trusting these records later. Needs a SOA in the authority section (it names
// the zone and bounds the negative TTL) or the response is ignored.
denials.insert_validated(&response);

// Answer from a cached gap, or None to go and ask. None is always safe and is
// what comes back whenever anything is in doubt.
if let Some(s) = denials.synthesize(&qname, qtype) {
    // s.rcode     -> NoSuchDomain, or Ok for NODATA
    // s.authority -> SOA + the proof records, TTLs already counted down
    // s.ttl       -> min(proof remaining, SOA negative TTL)
}
```

```rust
// The positive half (RFC 8198 §5.3). Same precondition: Secure answers only.
denials.insert_validated_wildcard(&response);

if let Some(w) = denials.synthesize_wildcard(&qname, qtype) {
    // w.answers   -> the wildcard's records, re-owned onto qname, TTL counted down
    // w.authority -> the NSEC proving qname absent, so a client can check it
}
```

Deliberately refused, each for a reason worth keeping: QTYPE ANY and RRSIG;
anything below a delegation; NODATA at a delegation for any type but DS;
opt-out NSEC3 spans (rejected at insert); NXDOMAIN without a wildcard denial; and
a wildcard answering for a name deeper than the one label it reaches.

## Quick reference: managed trust anchors

```rust
// Load, or seed from whatever anchors are configured. Fatal on a corrupt file:
// forgetting anchor state is not like forgetting a zone serial.
let mut managed = ManagedAnchors::load_or_seed(path, &configured, now)?;

// Feed it a DNSKEY RRset that VALIDATED — this checks no signatures itself, and
// unvalidated input here hands over the trust anchor set. `self_signers` is the
// subset that signed the RRset, which is the only basis for a revocation.
let signers = rfc5011::self_signers(zone, &response.answers, now);
for change in managed.observe(zone, &keys, &signers, now) { /* log it */ }

managed.save(path)?;                     // write before trusting, always
anchors.replace(managed.trust_anchors()); // SharedAnchors: live, no restart

// When to ask again (RFC 5011 §2.3), bounded at both ends.
rfc5011::query_interval(original_ttl, signature_remaining);
rfc5011::retry_interval(original_ttl, signature_remaining);
```

The order matters: the file is written *before* the live set is replaced, because
validating against keys we could not record would forget them on restart — which
is the failure the file exists to prevent.

## Quick reference: replication

```rust
// The client half of a transfer. All three open a TCP connection and time out.
xfr::fetch_soa(master, "example.com.", key.as_ref()).await?;   // -> u32 serial
xfr::fetch_zone(master, "example.com.", key.as_ref()).await?;  // -> Zone

// Incremental. The master may answer with the whole zone whatever you ask, so
// all three outcomes have to be handled — this is a preference, not a demand.
match xfr::fetch_changes(master, &held, key.as_ref()).await? {
    xfr::IxfrOutcome::UpToDate(serial) => {}
    xfr::IxfrOutcome::Updated { zone, steps, missing_deletions } => {}
    xfr::IxfrOutcome::FullTransfer(zone) => {}
}

// Or drive the assembling yourself, message by message, with no socket.
let mut assembler = xfr::AxfrAssembler::new("example.com.");
if assembler.accept(&msg)? == xfr::Progress::Complete {
    let zone = assembler.into_zone()?;   // errors if the closing SOA never came
}
// The incremental one is the same shape, and `into_outcome` takes the version
// the request was made from — applying to anything else builds a zone that
// never existed.
let mut assembler = xfr::IxfrAssembler::new("example.com.");
if assembler.accept(&msg)? == xfr::Progress::Complete {
    let outcome = assembler.into_outcome(&held)?;
}

// Policy: when to ask, when to give up, what to remember.
secondary::MasterSpec::parse("example.com@192.0.2.1:53#transfer.key.")?;
let timers = secondary::RefreshTimers::from_zone(&zone).unwrap_or_default();
timers.after_success();  timers.after_failure();
timers.has_expired(last_contact, now);          // -> stop serving the zone
remote_serial.is_newer_than(ours);              // RFC 1982; `>` will not compile

let mut state = secondary::StateFile::load(&secondary::state_file_path(dir));
state.get("example.com.", master);              // Option<&TransferState>
state.record(TransferState { .. })?;            // upsert + atomic rewrite

// Outbound increments. The log is derived from the zone map: record the step in
// the same breath as the swap, or an IXFR describes a zone we do not serve.
let mut deltas = ixfr::DeltaLog::new();
deltas.note_change(previous_version, &new_version);
deltas.forget("example.com.");                  // a zone we stopped serving
ixfr::apply_changes(&base, &deleted, &added, &new_soa);  // -> (Zone, removed)
match ixfr::ixfr_response(&request, &zone, &deltas)? {
    ixfr::IxfrResponse::UpToDate(messages) => {}          // one SOA
    ixfr::IxfrResponse::Incremental { messages, .. } => {}
    ixfr::IxfrResponse::FullTransfer { messages, why } => {}  // always allowed
}
```

Nothing here trusts what arrives: a transfer must open and close with the apex
SOA, every record must be in bailiwick, and a delta chain with a gap is refused
rather than partially applied. When adding to this, keep that posture — the
failures it prevents are all invisible after the fact.

## Quick reference: writing a zone, and writing a file

```rust
// Serialize a zone. Fails only on something this format cannot express — in
// practice an owner name needing escapes the parser does not read back.
let text: String = zone_writer::zone_to_string(&zone)?;
zone_writer::write_zone_file(&zone, Path::new("/var/db/example.com.zone"))?;
zone_writer::record_to_string(&record)?;   // one line, for logs and diffs

// Replace a file atomically: temporary sibling -> fsync -> rename. Use this for
// every piece of persisted state, not just zones (the step-3 sidecar included).
persist::write_atomically(path, bytes)?;
persist::write_atomically_str(path, &text)?;
```

What comes back out is byte-identical to what went in, including for records this
library cannot parse — that is the property to preserve when touching either
module, because a signed RRset re-spelled differently is a bogus one. Do not add
a "prettier" rendering without re-checking it against the re-encode guard in
`rdata_to_string`.
