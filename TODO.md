# rdns — TODO / Next Steps

Working notes for picking this up cold: what is open, what state the tree is in,
how to run it, and how to check a change on the platform the development machine
does not compile.

**The three files, and which question each answers.** This one says *what is
open*. `CLAUDE.md` says *which mistakes this codebase has already made* and the
rules that follow from them — read it before planning; its first rule is why a
green suite here has twice not meant what it looked like. `docs/spec/` says
*what the code actually does*, in seven files derived by reading it rather than
by reading intent, with every known RFC deviation and gap collected in one
table. `docs/architecture/` says *why the code has that shape*, one file per
topic, indexed under "Architecture" at the end of this page.

**A fourth file as of 2026-09-05: `docs/CLOSED_WORK.md`, one file per number
in `docs/closed/` since 2026-10-03**, beside `docs/issues/` for open items;
`docs/closed/log.md` says why it was split. Everything finished
lives there — ~~twenty-eight numbered sections covering thirty-one numbers~~, and
the log of what landed, verbatim, strike-throughs and wrong claims included.
`ls docs/closed/[0-9]*.md | wc -l` is the count, rather than a number
written here: the struck one was already wrong when it was written on 2026-09-05
(there were twenty-nine sections, not twenty-eight), and what the "thirty-one
numbers" counted is not recoverable — #5, #8 and #9 are closed with no section
of their own, and #21 had a section in *this* file until it closed on 2026-09-29. That is the ninth time a
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

Seven items. #171-#185 were filed 2026-10-05 from a comparison against
BIND, Knot, Unbound and PowerDNS, each claim checked against the code before
filing; #186-#192 came out of triaging the first batch, #193 out of closing
#173, #194 out of re-reading #190 and #192, #195-#198 out of a review on
2026-10-08, #199 and #200 out of triaging #197. #181 was closed wontfix in
triage; #171-#174, #176, #179, #183, #184, #186, #187, #189, #191, #178,
#188, #175, #177, #180 and #182 closed 2026-10-07, and #193, #195, #196, #197
and #199 2026-10-09, #198 2026-10-10. #201-#205 were filed and closed
2026-10-10 from a delivery-pipeline review, #206 out of closing #203, #207
out of the Linux run after it:

- #185 the UDP path: CPU per query below saturation (185b, needs-info); 185a
  closed, 185c and 185d wontfix.
- #200 `CLAUDE.md` is written in the register it forbids in comments; split
  into rules and `docs/LESSONS.md` (enhancement, ready for human).
- #206 whether `perf.yml` can gate: needs hosted A/A runs (needs-info).
- #207 one Linux test run in eleven failed, test unidentified (needs-info).

Deferred 2026-10-08 by the owner, not needed now; each file's "Deferred"
section holds what was found before parking:

- #190 Windows service: implemented (`36f2353`); the four SCM criteria and
  190a-190c unrun.
- #192 no Windows Event Log sink; both crate shapes measured.
- #194 no Windows installer; blocked on a release artifact.

The history this section accumulated — how each review's items were found and
closed, the push and CI record, the stale-preamble lesson and the five claims
on this page that were wrong — moved verbatim to `docs/closed/log.md` on
2026-10-04, under "What 'What is open' said".

- **#21** — the four deliberate RFC deviations and the not-implemented list,
  closed 2026-09-29 into `docs/closed/021.md`. **Not a queue.** It exists so
  the next person to notice one finds the decision instead of re-deriving it.
  If one is ever taken up it gets its own number.

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
| `rdnsctl`        | control client for a running `rdnsd` or `rdnsr`; a named pipe on Windows |
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
`docs/closed/log.md`) and the entry in
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
`allocations` prints **forty-nine** measurements — the number
`cargo test -p rdns --test allocations -- --nocapture` puts on stdout, and the
only one on this line that a command answers. ~~forty-two measurements,
thirty-two of them exact~~ was the pair here until 2026-09-13 and was wrong on
both counts; ~~twenty-nine and twenty~~ before #27 and #29 landed, twenty-two
and fourteen before the shapes added on 2026-08-31, nineteen and thirteen
before that, and the claim of "fourteen exact" at the start was never counted
and was wrong both ways. **Five pairs, four of them stale, and the fifth is
gone**: how many of the forty-nine are asserted exactly is a property of the
file and not of a `grep` — one helper writes `expected..=expected` and is
called twice — so the answer is to read `rdns/tests/allocations.rs`. One
measurement (`verify a DNSKEY RRset with two candidate signatures`) is asserted
as `0..=u64::MAX`: printed on purpose and asserted on purpose not at all,
because §10 found it is a time problem and not a count problem.
`no_input_panics` runs 1,506 mutated messages through the pre-authentication
path — 1.4 million of them when soaked. A test count is a poor summary of a
suite and this is where it shows.

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

~~One whole answer — parse, look up, build, serialize — is
**522 ns**~~ **Parsing a query and writing its zone answer is 190 ns**
(#150, 2026-10-02). The 522 ns bench cloned a parsed `DnsMessage`, filled its
answers and serialized it, which is neither daemon's path; it read 444 ns the
day it was replaced by one through `zone_answer::write`. The
`sendto`+`recvfrom` pair around it is **3.6-4.1 µs**. So
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

# Interoperability against BIND, Knot, NSD and Unbound (#43). One docker compose
# network, `internal: true` and no published ports, so nothing it runs is
# reachable from off the machine; `contained` asserts that four ways before any
# scenario starts. 158 assertions, and the peers' versions are printed by every
# run because "interop passed" without them names nothing.
tests/interop/run.sh all            # images, setup, every scenario; leaves it up
tests/interop/run.sh 43c            # one scenario against a network already up
tests/interop/run.sh shell          # a prompt inside the network
tests/interop/run.sh down           # and give the volumes back

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
# `rdns/benches/answer_path.rs` first: one zone answer is ~0.2 µs and the
# sendto+recvfrom pair around it is ~4 µs, so everything this measures is about
# 6% of a query and a 20% win in it is worth 1% end to end.
cargo bench -p rdns
cargo bench -p rdns -- --save-baseline before   # then change something
cargo bench -p rdns -- --baseline before        # and compare against it

# What a *fleet* costs, which nothing above measures: load time and memory for a
# zone of a million records, signing it, verifying it, how many zones one process
# holds, and what reloading them all costs (#44c). `#[ignore]`d and refused in
# debug — the default run is about 45 seconds and peaks near a gigabyte. The
# numbers it produced are under #44c; the knobs are so a smaller box can take the
# same measurement.
cargo test --release -p rdns --test scale -- --ignored --nocapture
RDNS_SCALE_RECORDS=100000 RDNS_SCALE_VERIFY=1000 cargo test --release -p rdns --test scale -- --ignored --nocapture

# What a policy feed costs to install and to refresh (#57d, #57e, #71). Three
# measurements that take turns, because the recipe selects all of them and
# libtest would otherwise run three million-rule runs at once (#71b).
cargo test --release -p rdns --test rpz_install -- --ignored --nocapture
RDNS_RPZ_RULES=100000 cargo test --release -p rdns --test rpz_install -- --ignored --nocapture

# What a zone's records cost to hold, to copy and to parse (#71e, #71f): what a
# `Zone::clone` is made of against an arena's floor, and what a feed's load is
# made of — 613 ms and eight allocations per record at a million rules.
cargo test --release -p rdns --test record_storage -- --ignored --nocapture
RDNS_RECORDS=100000 cargo test --release -p rdns --test record_storage -- --ignored --nocapture

# The two probes, which measure one thing each and are not part of any suite.
# Their headers carry what they measured and when; read those before quoting a
# number. Arguments are the multipliers, so a run is a table row.
cargo run --release -p rdns --example zone_lookup_probe -- miss 100000   # #11, #22
cargo run --release -p rdns --example nsec3_cache_probe -- 150 115       # #23

# A third, which measures octets rather than time, so it takes no arguments and
# reads the same on every machine: what the requests an operator sends weigh,
# against the admission caps above.
cargo run --release -p rdns --example request_size_probe                 # #40f
cargo run --release -p rdns --example request_size_probe -- 512          # the old cap

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

# The largest request each transport accepts. Both daemons default to 4096 on UDP
# — which is at or above what they advertise they can reassemble in every reply's
# OPT (RFC 6891 §6.2.4), so the cap cannot be set below that — and 16 KiB on TCP.
# Over the cap is dropped in silence, so the effective pair is in the startup
# banner. Raise the UDP one for a deployment whose signed UPDATEs are large:
# measure with `cargo run --release -p rdns --example request_size_probe`, which
# weighs the requests an operator actually sends (a 2048-bit DKIM rotation is 566
# octets signed, an ACME order with ten SANs 898).
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone   --max-udp-request 8192 --max-tcp-request 32768

# The two UDP *reply* sizes, which are the other half of the same question and
# were hardcoded until #41. --udp-payload-size is what every reply's OPT says
# this host can reassemble; --max-udp-response is the largest datagram it will
# send, and the client's own advertisement is honoured only down to it. Both
# default to 1232, which is where BIND, Knot, NSD and Unbound all landed after
# DNS Flag Day 2020, and both are floored at 512. Over the reply cap the answer
# is an empty TC=1 and the client asks again over TCP, which is never capped.
# What this server's own answers weigh, so the number can be chosen rather than
# copied: `cargo test -p rdnsd response_size -- --nocapture`.
cargo run -p rdnsd -- --port 15353 --zone-file example.com.zone   --udp-payload-size 1232 --max-udp-response 1232

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
# unbound-control do; there is no control port. On Windows a named pipe,
# --control-socket '\\.\pipe\rdnsd'.
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

# The same settings in a file, and its dry run. `[[rpz.feeds]]` is the one thing
# the flags cannot say: a policy per feed, so a new feed is measured in
# `passthru` while the rest stay enforced.
cargo run -p rdnsr -- --config ./rdnsr.toml
cargo run -p rdnsr -- --config ./rdnsr.toml --check-config   # dry run, exits 0
#
#   [rpz]
#   policy = "given"            # what a feed that says nothing inherits
#   notify-from = ["192.0.2.1"]
#
#   [[rpz.feeds]]
#   file = "court-order.rpz"
#
#   [[rpz.feeds]]
#   file = "new-feed.rpz"
#   policy = "passthru"
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
cargo deny --all-features check                 # needs cargo-deny 0.17+
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

Which numbers are open is in "What is open" above, and only there. This line
carried a second copy of the list and it was three numbers stale — #107, #111
and #115 had closed under it — which is what a sentence claiming to be the one
place costs when it is not.
Each open item is `docs/issues/NNN.md` and each closed one `docs/closed/NNN.md`,
under its own number; the numbers are stable identifiers referenced from the
code, so a file moves rather than being renumbered.

### Where to pick up next

Everything here is a choice, not a queue, and this heading is deliberately
short. Its own previous contents made the argument: four strike-throughs
accumulated in a single day, under a sentence observing that "a paragraph naming
what is next is wrong as soon as somebody does it". It was right, so the
paragraph is gone.

What is left worth saying is the rule the chain kept demonstrating. **Take the
item that could invalidate the others before the ones that add to them.** #43
was that item — a year of careful work that had never spoken to BIND had one
untested assumption under all of it — and it went first for that reason, then
proved #46's fix and all three of #42's stages on the way out. ~~Of what remains,
#44 and #45 are lists of absences rather than defects, and #21 is not a queue at
all.~~ **#44 closed in full on 2026-09-12 and the "absences rather than defects"
half of that was wrong twice over** — see its row under "Closed work". #45 is
still a list of absences and #21 is still not a queue.

Then, in order and for stated reasons:

1. ~~**44b**, Extended DNS Errors. The smallest row on the page and the one an
   operator notices first.~~ **Done 2026-09-12.** It was the one an operator
   notices first and it was not the smallest; the row says what the difference
   cost.
2. ~~**44a**, catalog zones — the row that moves the answer from "a nice server"
   to "a server I could run a fleet of".~~ **Done 2026-09-12**, the consumer
   side; the producer side needed no code, because a catalog is an ordinary
   zone. Left behind: **#48** and **#49**.
3. ~~**#42's stages**: 42a first, because it costs 7 packages and both of the
   others are built on it; 42b next, because `quinn` supplies streams and
   RFC 9250's framing is `rdns::framed` already; 42c last and largest, because
   it is the only one carrying a second change — the metrics server folding onto
   `hyper`.~~ **All three done 2026-09-12, in that order and for those reasons**,
   which held. **44d** (XFR over TLS) is the fourth stage that row named and is
   ~~what is left of it: the rustls plumbing and the ALPN dispatch are in place
   and a transfer already works over DoT and DoQ unchanged, so what it still
   needs is the policy half — which keys and which peers may transfer over which
   transport.~~ **Done 2026-09-12**, and the policy half was the smaller one: the
   client half had no code at all, because nothing here had ever spoken TLS as a
   client.
4. ~~**44c**, the scale measurement, whenever somebody wants a number rather
   than a feature.~~ **Taken 2026-09-12**, and it was not a number rather than a
   feature: the four figures it was filed for are unremarkable and the fifth is
   **#50**.
5. ~~**#50**, which is where the rule at the top of this heading points now. It
   is the only defect on the page, and the only row anywhere in #44 or #45 that
   stops a deployment rather than limiting one.~~ **Done 2026-09-12**, and it
   was: 112.68 s to verify twenty thousand RRsets became 0.65. ~~What it left is
   **#53**, which is not a defect — it is the same check, asked whether it needs
   to run on a zone we signed ourselves.~~ **#53 closed 2026-09-13**, and it was
   the same check: it runs once per zone per set of signing keys now, so a
   re-signing tick pays for signing and nothing else.

~~**#45 is a different product decision**, not a queue position: it is what an
ISP needs, and 45a (RPZ) is a legal gate rather than a nice-to-have for anyone
with blocking obligations. 45e is a decision to take rather than work to
schedule.~~ **Closed 2026-09-13**, all five rows in one day, and both halves of
that paragraph held: 45a went first because of the gate, and 45e was a decision
whose answer was no. 45a left #56 and #57, and 45b left #58; 45c and 45d left
nothing, and 45d's mechanism is half of what #58 will want.

~~The certificate story in 42a is still the part with no decision behind it.~~
**Decided 2026-09-12**, and the decision was partly to decline: a renewal is a
reload of one shared `CertificateStore`, and expiry is deliberately not parsed —
the section says why an X.509 parser whose whole output is a log line is the
wrong trade when the symptom is already a counter.

> **1. ~~Push, and read the five CI jobs nobody has ever read.~~ Read 2026-09-11,
> and the one job that cannot run here is the one that had been broken.** ~~Ask
> `git rev-list --count origin/main..HEAD` how much is waiting; it was 49 on
> 2026-09-05.~~ **Pushed 2026-09-09 at `acd229e`**, so the count is 0. ~~Reading
> the runs is what is left, and a session cannot do it from here: there is no
> `gh` on this machine.~~ **Reading a run starts no job and costs no minutes**,
> so this half was never the owner's call — only the push is. Of the seven job-runs a push costs, five had
> never been looked at: msrv (1.95), deny, the container image, the `dhat-heap`
> feature build, and clippy on *Linux* — though that last one is checked by hand
> here and is clean as of ~~2026-09-06~~ **2026-09-08**, on the half of the tree
> Windows cannot compile. **Pushing is still the owner's call and not a
> session's**: `CLAUDE.local.md` says why a push costs something and who makes it.
>
> **Read again 2026-09-20, and two jobs were red**: `35463448583` (`13f3b47`,
> 2026-09-19), the first push since the TLS work landed. `image` and `deny`, the
> two no `cargo` invocation here can stand in for, and the `image` failure was
> #31's word for word. Both fixed and closed as **#91**, which is also where the
> `cargo deny` half is written down.
>
> **What the last all-green run says** (`34530980969`, `431acd0`, 2026-09-10):
> all seven green. msrv passes on toolchain 1.95; `cargo-deny` 0.20.2 reports "advisories
> ok, bans ok, licenses ok, sources ok"; the image builds, answers `--version`
> with `rdnsd 0.1.0 (g431acd0c3de0)` — so the `RDNS_GIT_DESCRIBE` build-arg works
> and it is not the bare `0.1.0` a missing one gives — serves `/healthz` and
> `/readyz` to `curl -sf`, and logs "drained cleanly" on stop. **And a
> cross-check worth more than the ticks**: CI's own counts at that commit are
> **908 on Windows and 924 on Ubuntu**, which is exactly what the development
> machine measured, so the convention of quoting both numbers survives a third
> machine that shares nothing with it.
> A naive total of that log reads ~1,500 because two further invocations follow
> `--workspace`: the allocations test (1) and `cargo test -p rdns --benches`
> (597 Ubuntu, 594 Windows).
>
> **What reading it found, which is why the item existed.** The four pushes
> before that one all failed — 2026-09-08 09:31 and 10:30, 2026-09-09 09:35 and
> 09:54 — and every one of them failed in **only** the container-image job, with
> `failed to read /src/rdns-core/Cargo.toml`. #31 split `rdns-core` and
> `rdns-transport` out on 2026-09-05 and the Dockerfile's `COPY` list was never
> told, so the image was unbuildable from the first push after that crate split
> until `Copy the two library crates into the container build` on 2026-09-09.
> **`image` is the one job the recipe above cannot stand in for** — every other
> job is `cargo` something a developer already runs, and this one needs a
> container runtime — and it is the one that broke. `CLAUDE.md` §1's rule about a
> green suite on one platform, arriving a second time as a green *tree* with a
> red job nobody opened.
>
> The last run that was read was the first one, on 2026-08-01, and it found two
> things — a Windows test that was wrong rather than code that was, and
> `actions/checkout@v4` on a runner that had moved to Node 24. Both fixed in
> `8758476` and ~~unpushed since~~ **pushed 2026-09-09**, five weeks later.
>

**Read `benches/answer_path.rs`'s header before quoting anything from it.** One
whole answer is ~~522 ns~~ 190 ns (#150) and one `sendto`+`recvfrom` pair is
3.6-4.1 µs, so the
entire benchmark suite covers about 6% of what a query costs — the context that
stops a 20% win in it being reported as a 20% win.

---

## Closed work

One line each. The reasoning, the RFC citations and the verification are in the
commit that closed it and in `docs/closed/NNN.md`, which holds every section
below in full under the same number.

**"Every one" has had to be corrected three times**, each time because a section
closed and sat under "Open work" for a few hours or a day before it was moved.
The exceptions used to be listed here and struck through as they went; they are
not any more, for the reason given under "What is open" — a count that stopped
being current teaches nobody anything, and the row for each number already says
where its section is. What is worth keeping is the shape: a section is closed in
one commit and moved in another, and the gap between them is when this sentence
is wrong. **The numbers are stable identifiers** —
referenced from 88 doc comments in the tree and from each other — so they are
moved, never renumbered.

**Read this table, not a summary of it.** Eight times by its own count, a
sentence at the top of this page has said what was open and been wrong within
the week; the record is under "How the queue kept going stale" in
`docs/closed/log.md`.

| # | what it was | outcome |
|---|---|---|
| **1** | recursor follow-ups | done · [`docs/closed/001.md`](docs/closed/001.md) |
| **2** | DNSSEC follow-ups | done · [`docs/closed/002.md`](docs/closed/002.md) |
| **3** | NSEC3 salt and iterations | done · [`docs/closed/003.md`](docs/closed/003.md) |
| **4** | zone lookup | done · [`docs/closed/004.md`](docs/closed/004.md) |
| **5** | smaller items: AXFR, TSIG, NOTIFY, IXFR, amplification, negative caching, `$INCLUDE`, TXT framing | done. No section of its own; the entries are in `docs/closed/log.md`'s "Done so far" |
| **6** | special-use names in `rdnsr` | done · [`docs/closed/006.md`](docs/closed/006.md) |
| **7** | the secondary role, in six steps | **all six done 2026-08-03.** · [`docs/closed/007.md`](docs/closed/007.md) |
| **8** | what signing turned up — the re-signing timer and its serial | done. Settled by reading BIND, Knot, PowerDNS and NSD, which converge on something better than either option written down |
| **9** | what a five-way review found: 48 defects in six groups (9a-9f) | **all done 2026-07-27 → 2026-08-01.** No section: the patterns became `CLAUDE.md`, which is the useful artefact, and the 2,435 lines of finding text are in `git log -p TODO.md` |
| **10** | dynamic UPDATE (RFC 2136) | **done 2026-08-03** · [`docs/closed/010.md`](docs/closed/010.md) |
| **11** | data layout and CPU cache friendliness | **answered no, 2026-08-04.** · [`docs/closed/011.md`](docs/closed/011.md) |
| **12** | pre-authentication panics | **audited 2026-08-01.** · [`docs/closed/012.md`](docs/closed/012.md) |
| **13** | making illegal states unrepresentable | **done 2026-08-02** · [`docs/closed/013.md`](docs/closed/013.md) |
| **14** | `Serial`, QR as a type, sealing `RecordData` | **all three done 2026-08-02** · [`docs/closed/014.md`](docs/closed/014.md) |
| **15** | collapsing `DName`/`UnpackedDName` | **withdrawn 2026-08-03** · [`docs/closed/015.md`](docs/closed/015.md) |
| **16** | simplifications: `Nsec3`'s fallibility, splitting `parse_into`, a duplication that must stay | **16b done, 16a corrected-and-withdrawn, 16c recorded as not-to-fix, 2026-08-02.** · [`docs/closed/016.md`](docs/closed/016.md) |
| **17** | the TCP length prefix wraps to 0 on a TSIG-signed answer near 64 KB | **fixed 2026-08-03.** · [`docs/closed/017.md`](docs/closed/017.md) |
| **18** | `rdnsr` has none of the operational shell | **fixed 2026-08-03.** · [`docs/closed/018.md`](docs/closed/018.md) |
| **19** | the 2026-08-03 review's smaller items, 19a-19h | **closed 2026-08-03.** · [`docs/closed/019.md`](docs/closed/019.md) |
| **20** | `rdnsd/src/main.rs` is one file and eleven subsystems | **done 2026-08-03** · [`docs/closed/020.md`](docs/closed/020.md) |
| **21** | the deliberate RFC deviations and the not-implemented list | **filed 2026-08-03, closed 2026-09-29, wontfix.** · [`docs/closed/021.md`](docs/closed/021.md) |
| **22** | the zone lookup is hash-bound | **closed 2026-09-05.** · [`docs/closed/022.md`](docs/closed/022.md) |
| **23** | `NsecCache::synthesize` hashes once per cached NSEC3 record, under one mutex | **fixed 2026-08-04** · `9715c3c` · [`docs/closed/023.md`](docs/closed/023.md) |
| **24** | three costs that grow with something the operator chose | **all three fixed 2026-08-05.** · [`docs/closed/024.md`](docs/closed/024.md) |
| **25** | per-answer waste on paths #9e already measured | **closed 2026-09-04** · [`docs/closed/025.md`](docs/closed/025.md) |
| **26** | helpers written twice, and hand-rolls with a standard spelling | **closed 2026-09-04** · [`docs/closed/026.md`](docs/closed/026.md) |
| **27** | what a zero-allocation answer path would take | **closed 2026-09-05** · [`docs/closed/027.md`](docs/closed/027.md) |
| **28** | work the answer path does and need not | **28a-28c done and 28d answered no, 2026-09-01.** · [`docs/closed/028.md`](docs/closed/028.md) |
| **29** | the resolver half never got #27's pass | **filed and closed 2026-09-04** · [`docs/closed/029.md`](docs/closed/029.md) |
| **30** | the two daemons' transports are one transport written twice | **closed 2026-09-05.** · [`docs/closed/030.md`](docs/closed/030.md) |
| **31** | where a crate boundary would pay | **done 2026-09-05.** · [`docs/closed/031.md`](docs/closed/031.md) |
| **32** | `Shell`, `Served` and the other unnamed bags | **closed 2026-09-05.** · [`docs/closed/032.md`](docs/closed/032.md) |
| **33** | a fourth pass: duplication, generics, and where the modules are cut | **closed 2026-09-06** · [`docs/closed/033.md`](docs/closed/033.md) |
| **35** | SVCB and HTTPS (RFC 9460) | **filed and closed 2026-09-07** · [`docs/closed/035.md`](docs/closed/035.md) |
| **36** | #13e's `Name` half: names as wire octets | **filed and closed 2026-09-07** · [`docs/closed/036.md`](docs/closed/036.md) |
| **34** | DNAME (RFC 6672) | **filed and closed 2026-09-06** · [`docs/closed/034.md`](docs/closed/034.md) |
| **37** | where a module folder pays, and where it is motion | **filed and closed 2026-09-08** · [`docs/closed/037.md`](docs/closed/037.md) |
| **38** | a structural review, and what it left | **filed and closed 2026-09-09 → 2026-09-10** · [`docs/closed/038.md`](docs/closed/038.md) |
| **39** | `rdnsd` answers through two dispatchers | **filed and closed 2026-09-10 → 2026-09-11** · [`docs/closed/039.md`](docs/closed/039.md) |
| **41** | nothing capped the UDP response, and the sizes were hardcoded | **filed and closed 2026-09-11** · [`docs/closed/041.md`](docs/closed/041.md) |
| **42** | the three encrypted transports | **filed 2026-09-11, closed 2026-09-12** · [`docs/closed/042.md`](docs/closed/042.md) |
| **48** | a catalog's `group` property is read and not acted on | **filed 2026-09-12, closed 2026-09-13.** · [`docs/closed/048.md`](docs/closed/048.md) |
| **49** | nothing on the control socket says a zone came from a catalog | **filed 2026-09-12, closed 2026-09-13.** · [`docs/closed/049.md`](docs/closed/049.md) |
| **45** | what an ISP would find missing in `rdnsr` | **filed 2026-09-11, closed 2026-09-13** · [`docs/closed/045.md`](docs/closed/045.md) |
| **46** | `rdnsd` could not sign a NOTIFY | **filed and closed 2026-09-12** · [`docs/closed/046.md`](docs/closed/046.md) |
| **43** | nothing here had ever answered another implementation | **filed 2026-09-11, closed 2026-09-12.** · [`docs/closed/043.md`](docs/closed/043.md) |
| **50** | verifying a signed zone at load was quadratic in the zone | **filed and closed 2026-09-12** · [`docs/closed/050.md`](docs/closed/050.md) |
| **53** | a zone was verified at load even when this server had just signed it | **filed 2026-09-12, closed 2026-09-13** · [`docs/closed/053.md`](docs/closed/053.md) |
| **51** | XoT authorized its client by ACL and TSIG, never by certificate | **filed 2026-09-12, closed 2026-09-13** · [`docs/closed/051.md`](docs/closed/051.md) |
| **54** | a dispatcher could not say which encrypted transport a message arrived on | **filed 2026-09-12, closed 2026-09-13** · [`docs/closed/054.md`](docs/closed/054.md) |
| **55** | nothing generated CDS or CDNSKEY, so a KSK rollover still needed a human | **filed 2026-09-12, closed 2026-09-13** · [`docs/closed/055.md`](docs/closed/055.md) |
| **56** | an RPZ's NSDNAME and NSIP triggers were counted and not enforced | **filed and closed 2026-09-13** · [`docs/closed/056.md`](docs/closed/056.md) |
| **40** | the internal APIs, asked whether they fit each other | **filed and closed 2026-09-10 → 2026-09-11** · [`docs/closed/040.md`](docs/closed/040.md) |
| **52** | a rate-limit test is a coin toss at a second boundary | **filed and closed 2026-09-12** · [`docs/closed/052.md`](docs/closed/052.md) |
| **47** | a NOTIFY reply carried no OPT record | **filed and closed 2026-09-12** · [`docs/closed/047.md`](docs/closed/047.md) |
| **44** | what an operator would find missing in `rdnsd` | **filed 2026-09-11, closed in full 2026-09-12** · [`docs/closed/044.md`](docs/closed/044.md) |
| **60** | a string continuation flattened into spaces was an operator-facing defect | **filed 2026-09-13, closed 2026-09-14.** · `946899e` · [`docs/closed/060.md`](docs/closed/060.md) |
| **61** | a million-rule reload spent its time building the index, not parsing | **filed and closed 2026-09-14.** · `6ced88c` · [`docs/closed/061.md`](docs/closed/061.md) |
| **62** | three unbounded-input traps behind an assumption nothing enforced | **filed and closed 2026-09-14.** · `93b3cb0`, `c222246`, `2f70ba1` · [`docs/closed/062.md`](docs/closed/062.md) |
| **65** | every load re-signed every zone from scratch | **filed and closed 2026-09-14** · [`docs/closed/065.md`](docs/closed/065.md) |
| **63** | `rdnsr` had 39 flags and no config file | **filed 2026-09-14, closed 2026-09-15** · [`docs/closed/063.md`](docs/closed/063.md) |
| **66** | `rdnsc` could not write what it transferred | **filed and closed 2026-09-15.** · `c6ee084`, `ca19761`, `e26a479` · [`docs/closed/066.md`](docs/closed/066.md) |
| **67** | the crate split, re-measured once a small binary took crypto | **filed and closed 2026-09-15.** · `983e4fe`, `8f64072`, `7187af4`, `c0238ff` · [`docs/closed/067.md`](docs/closed/067.md) |
| **64** | one dynamic UPDATE was five O(zone) passes | **filed 2026-09-14, closed 2026-09-16** · [`docs/closed/064.md`](docs/closed/064.md) |
| **59** | nothing here demanded a client certificate for a transfer | **filed 2026-09-13, closed 2026-09-16** · [`docs/closed/059.md`](docs/closed/059.md) |
| **70** | the metrics endpoint did not enforce RFC 9112 §3.2, and its header said it did | **filed and closed 2026-09-16** · [`docs/closed/070.md`](docs/closed/070.md) |
| **57** | a policy zone arrived as a file somebody else wrote, not as a transfer | **filed 2026-09-13, closed 2026-09-16** · [`docs/closed/057.md`](docs/closed/057.md) |
| **69** | four accept loops ended on any error, where the UDP side had a helper | **filed and closed 2026-09-16** · [`docs/closed/069.md`](docs/closed/069.md) |
| **71** | applying a forty-record change was sized by the zone, twice over | **filed 2026-09-16, closed 2026-09-19** · [`docs/closed/071.md`](docs/closed/071.md) |
| **72** | a zone's arena was filled from what the caller had just allocated | **filed and closed 2026-09-19** · [`docs/closed/072.md`](docs/closed/072.md) |
| **73** | a denial outlived the SOA beside it | **filed and closed 2026-09-19** · `35b1e8f` · [`docs/closed/073.md`](docs/closed/073.md) |
| **74** | `--check-config` did not name DoH | **filed and closed 2026-09-19** · `20b8dc8` · [`docs/closed/074.md`](docs/closed/074.md) |
| **75** | two of three answering paths returned past the epilogue | **filed and closed 2026-09-19** · `74019de` · [`docs/closed/075.md`](docs/closed/075.md) |
| **76** | `ScratchDir` existed three times | **filed and closed 2026-09-19** · `ab2ae3b` · [`docs/closed/076.md`](docs/closed/076.md) |
| **77** | what #73 and #75 left behind | **filed 2026-09-19, closed 2026-09-20** · `1a0422c`, `2d72c4c` · [`docs/closed/077.md`](docs/closed/077.md) |
| **85** | the library installed the process's log subscriber | **filed and closed 2026-09-20** · [`docs/closed/085.md`](docs/closed/085.md) |
| **86** | two error enums sat in the crate that could not name them | **filed and closed 2026-09-20** · [`docs/closed/086.md`](docs/closed/086.md) |
| **91** | both CI jobs no local `cargo` run covers were red | **filed and closed 2026-09-20** · [`docs/closed/091.md`](docs/closed/091.md) |
| **87** | the UDP request path read the wall clock, not `ServeContext`'s | **filed and closed 2026-09-20** · [`docs/closed/087.md`](docs/closed/087.md) |
| **88** | nothing measured `rdnsr`'s answer path | **filed and closed 2026-09-20** · [`docs/closed/088.md`](docs/closed/088.md) |
| **89** | a moved module left its doc comment on the next one | **filed and closed 2026-09-20** · `e26a479` · [`docs/closed/089.md`](docs/closed/089.md) |
| **79** | claims and code that outlived each other | **filed 2026-09-19, closed 2026-09-20** · [`docs/closed/079.md`](docs/closed/079.md) |
| **80** | two bools where the enum was already imported | **filed 2026-09-19, closed 2026-09-20** · [`docs/closed/080.md`](docs/closed/080.md) |
| **92** | twelve wall-clock reads outside any request path | **filed and closed 2026-09-20** · [`docs/closed/092.md`](docs/closed/092.md) |
| **90** | no test spawned either binary | **filed and closed 2026-09-20** · [`docs/closed/090.md`](docs/closed/090.md) |
| **83** | `rdnsd/src/main.rs` had grown two seams | **filed 2026-09-19, closed 2026-09-20** · [`docs/closed/083.md`](docs/closed/083.md) |
| **96** | a master that refuses the SOA probe was treated as unreachable | **filed and closed 2026-09-20** · [`docs/closed/096.md`](docs/closed/096.md) |
| **95** | nothing branched on a `TransferError` variant | **filed and closed 2026-09-20** · [`docs/closed/095.md`](docs/closed/095.md) |
| **93** | an answer's owner names carried this resolver's 0x20 scramble | **filed and closed 2026-09-20** · [`docs/closed/093.md`](docs/closed/093.md) |
| **94** | nothing enforced a DNSKEY's protocol field | **filed and closed 2026-09-20** · [`docs/closed/094.md`](docs/closed/094.md) |
| **97** | `cargo deny check` by hand checked less than the job that runs it | **filed and closed 2026-09-21** · `8f1be6e` · [`docs/closed/097.md`](docs/closed/097.md) |
| **98** | the agent-skill config pointed at a `CONTEXT.md` that was not there | **filed and closed 2026-09-21** · [`docs/closed/098.md`](docs/closed/098.md) |
| **99** | both daemons' dry run was a `return` at a line number, not the rule §15 states | **filed and closed 2026-09-21** · [`docs/closed/099.md`](docs/closed/099.md) |
| **100** | a dynamic UPDATE's own signatures were the only ones no run verified | **filed and closed 2026-09-21** · [`docs/closed/100.md`](docs/closed/100.md) |
| **103** | `server_table!` shared the field declarations and not the projection onto `Cli` | **filed and closed 2026-09-21** · [`docs/closed/103.md`](docs/closed/103.md) |
| **104** | four digest caches over one `FileDigest`, with the reasoning built on it copied | **filed and closed 2026-09-21** · [`docs/closed/104.md`](docs/closed/104.md) |
| **105** | `https::answer` charged the rate limiter whatever the caller asked for | **filed and closed 2026-09-21** · [`docs/closed/105.md`](docs/closed/105.md) |
| **106** | a DoH transfer was built in full and discarded | **filed and closed 2026-09-21** · [`docs/closed/106.md`](docs/closed/106.md) |
| **101** | the TSIG-rejection branch returned past the dnstap tail | **filed and closed 2026-09-21** · [`docs/closed/101.md`](docs/closed/101.md) |
| **102** | `Answered::refresh` survived thirteen exits by inspection | **filed and closed 2026-09-21** · [`docs/closed/102.md`](docs/closed/102.md) |
| **81** | what #63h's macro did not reach, and one more copy | **filed 2026-09-19, closed 2026-09-20** · [`docs/closed/081.md`](docs/closed/081.md) |
| **82** | two modules in the wrong place, and a `pub` with no ratchet | **filed 2026-09-19, closed 2026-09-20** · [`docs/closed/082.md`](docs/closed/082.md) |
| **84** | `to_prometheus_format` was 337 lines of one idiom | **filed 2026-09-19, closed 2026-09-20** · [`docs/closed/084.md`](docs/closed/084.md) |
| **78** | `rdnsr`'s query path lost work at three of its exits | **filed 2026-09-19, closed 2026-09-20** · [`docs/closed/078.md`](docs/closed/078.md) |
| **107** | eleven wall-clock reads inside a request path, in the crate #92 did not count | **filed 2026-09-21, closed 2026-09-22** · [`docs/closed/107.md`](docs/closed/107.md) |
| **108** | `min(SOA MINIMUM, the SOA's own TTL)` written five times | **filed 2026-09-21, closed 2026-09-24** · [`docs/closed/108.md`](docs/closed/108.md) |
| **109** | `struct Server` in the crate root, its implementation in `dispatch` | **filed 2026-09-21, closed 2026-09-24** · [`docs/closed/109.md`](docs/closed/109.md) |
| **110** | one-victim eviction scans left after `Halving` | **filed 2026-09-21, closed 2026-09-24** · [`docs/closed/110.md`](docs/closed/110.md) |
| **112** | price the reload cluster's constructors | **filed 2026-09-21, closed 2026-09-24** · [`docs/closed/112.md`](docs/closed/112.md) |
| **113** | #103's projection sweep stopped at `[server]` | **filed 2026-09-21, closed 2026-09-24** · [`docs/closed/113.md`](docs/closed/113.md) |
| **114** | the prefetch ran inside `Handler::handle`, before DoH's answer | **filed 2026-09-21, closed 2026-09-25** · [`docs/closed/114.md`](docs/closed/114.md) |
| **116** | `rdnsd`'s answering tests were in the crate root | **filed 2026-09-24, closed 2026-09-25** · [`docs/closed/116.md`](docs/closed/116.md) |
| **117** | `refresh` claimed the query path's storing; prefetch and DNS64 never fed the denial cache | **filed and closed 2026-09-25** · [`docs/closed/117.md`](docs/closed/117.md) |
| **118** | `answer_update` checked permission before the zone, and its doc claimed the RFC's order | **filed and closed 2026-09-25** · [`docs/closed/118.md`](docs/closed/118.md) |
| **119** | two UPDATE refusals no test reached, and an unreadable zone directory answered REFUSED | **filed and closed 2026-09-25** · [`docs/closed/119.md`](docs/closed/119.md) |
| **68** | a socket test failed once under a parallel suite | **filed 2026-09-15, closed 2026-09-25.** · [`docs/closed/068.md`](docs/closed/068.md) |
| **58** | serve-stale answered a dead upstream and not a slow one | **filed 2026-09-13, closed 2026-09-25.** · [`docs/closed/058.md`](docs/closed/058.md) |
| **120** | three timing flakes found verifying #68 | **filed and closed 2026-09-25.** · [`docs/closed/120.md`](docs/closed/120.md) |
| **122** | ratio tests took five of one side, then five of the other | **filed 2026-09-25, closed 2026-09-26.** · [`docs/closed/122.md`](docs/closed/122.md) |
| **121** | incremental signing took a key tag for a key | **filed 2026-09-25, closed 2026-09-26.** · [`docs/closed/121.md`](docs/closed/121.md) |
| **123** | two resolver tests timed out under load | **filed and closed 2026-09-26.** · [`docs/closed/123.md`](docs/closed/123.md) |
| **124** | `compression.rs`'s ratio test near its bound in debug | **filed and closed 2026-09-26.** · [`docs/closed/124.md`](docs/closed/124.md) |
| **125** | `--generate-keys` replaced a key file whose tag it collided with | **filed and closed 2026-09-26.** · [`docs/closed/125.md`](docs/closed/125.md) |
| **126** | `--generate-keys` left a KSK with no DS when the ZSK's write failed | **filed and closed 2026-09-27.** · [`docs/closed/126.md`](docs/closed/126.md) |
| **127** | a cached wildcard synthesis counted neither a hit nor a miss | **filed and closed 2026-09-27.** · [`docs/closed/127.md`](docs/closed/127.md) |
| **128** | RFC 1035 §4.3.5's refresh cycle was written twice and neither copy was tested | **filed 2026-09-27, closed 2026-09-28.** · [`docs/closed/128.md`](docs/closed/128.md) |
| **129** | `Caches` sealed its write side and left the read order to its callers | **filed and closed 2026-09-27.** · [`docs/closed/129.md`](docs/closed/129.md) |
| **130** | four UPDATE refusals had an EDE or rcode no test asserted | **filed 2026-09-27, closed 2026-09-28.** · [`docs/closed/130.md`](docs/closed/130.md) |
| **131** | a zone with two masters was withdrawn when one of them was down | **filed and closed 2026-09-27.** · [`docs/closed/131.md`](docs/closed/131.md) |
| **132** | a stale lookup served an older "yes" over a newer "no" | **filed and closed 2026-09-27.** · [`docs/closed/132.md`](docs/closed/132.md) |
| **133** | the fresh path could serve an older "no" over a newer "yes" | **filed and closed 2026-09-27.** · [`docs/closed/133.md`](docs/closed/133.md) |
| **134** | a cached RFC 8198 gap or wildcard outranked a newer answer for the name | **filed and closed 2026-09-27.** · [`docs/closed/134.md`](docs/closed/134.md) |
| **135** | a restarted `rdnsr` whose master was gone never reached EXPIRE | **filed and closed 2026-09-27.** · [`docs/closed/135.md`](docs/closed/135.md) |
| **136** | the resolver's tests reached it only through a loopback hierarchy | **filed and closed 2026-09-28.** · [`docs/closed/136.md`](docs/closed/136.md) |
| **137** | nothing tested fastest-first server order end to end | **filed 2026-09-28, closed 2026-09-29.** · `15d9add` · [`docs/closed/137.md`](docs/closed/137.md) |
| **138** | an NSEC3 salt over 255 octets was encoded with the wrong length | **filed and closed 2026-09-28.** · `9431916` · [`docs/closed/138.md`](docs/closed/138.md) |
| **139** | TSIG read a key name off the wire as lossy, unescaped text | **filed and closed 2026-09-28.** · `248bdc0` · [`docs/closed/139.md`](docs/closed/139.md) |
| **140** | an NSEC type bitmap folded its type names with the Unicode fold | **filed and closed 2026-09-28.** · `a40c305` · [`docs/closed/140.md`](docs/closed/140.md) |
| **141** | the config file refused a key reference the flags accept | **filed and closed 2026-09-28.** · `9f3524d` · [`docs/closed/141.md`](docs/closed/141.md) |
| **142** | poison recovery was spelled two ways | **filed and closed 2026-09-28.** · `a26a938` · [`docs/closed/142.md`](docs/closed/142.md) |
| **143** | fourteen `push_str(&format!(..))` in production code | **filed and closed 2026-09-28.** · `07d2719` · [`docs/closed/143.md`](docs/closed/143.md) |
| **144** | six copies inside one module each | **filed and closed 2026-09-28.** · `c34236e` · [`docs/closed/144.md`](docs/closed/144.md) |
| **145** | work done twice or thrown away | **filed and closed 2026-09-28.** · `1009089` · [`docs/closed/145.md`](docs/closed/145.md) |
| **146** | small idioms, one sweep | **filed and closed 2026-09-28.** · `1e6e39e` · [`docs/closed/146.md`](docs/closed/146.md) |
| **147** | a zone-file field past a name's RDATA was joined into the name | **filed and closed 2026-09-28.** · `a5ea7e8` · [`docs/closed/147.md`](docs/closed/147.md) |
| **148** | domain docs moved to the mattpocock layout | **filed 2026-09-29, closed 2026-09-30.** · [`docs/closed/148.md`](docs/closed/148.md) |
| **149** | eleven em dashes in comments were double-encoded | **filed 2026-09-30, closed 2026-10-01.** · `96f26dd` · [`docs/closed/149.md`](docs/closed/149.md) |
| **150** | the authoritative answer was split across the `rdns`/`rdnsd` seam | **filed 2026-10-01, closed 2026-10-02.** · `d19d6e5`, `66199ad` · [`docs/closed/150.md`](docs/closed/150.md) |
| **152** | the re-signing interval came back without the rule that chose it | **filed 2026-10-01, closed 2026-10-02.** · `3348cad` · [`docs/closed/152.md`](docs/closed/152.md) |
| **153** | the encrypted listeners were configured, bound and spawned in both daemons | **filed 2026-10-01, closed 2026-10-02.** · `34bfceb`, `2e248e5` · [`docs/closed/153.md`](docs/closed/153.md) |
| **154** | a cache entry's expiry had no type, and seven of eight constructions did not saturate | **filed 2026-10-01, closed 2026-10-02.** · `659ac8f` · [`docs/closed/154.md`](docs/closed/154.md) |
| **111** | the signing cost harness was a copy of `sign_zone_inner` and had drifted | **filed 2026-09-21, closed 2026-09-22** · [`docs/closed/111.md`](docs/closed/111.md) |
| **115** | two pieces of `rdnsd` prose that were wrong in the tree | **filed 2026-09-21, closed 2026-09-22** · `955504d`, `dc9d64ab` · [`docs/closed/115.md`](docs/closed/115.md) |
| **155** | the stream listeners' connection ceiling and idle timeout had no flag, and reaching the ceiling was invisible | **filed 2026-10-02, closed 2026-10-03.** · `05d4668` · [`docs/closed/155.md`](docs/closed/155.md) |
| **157** | the query and response limiters keyed on the exact peer, so a host rotating within its /64 was never limited | **filed 2026-10-02, closed 2026-10-03.** · `cccd5c0` · [`docs/closed/157.md`](docs/closed/157.md) |
| **158** | on a dual-stack socket, IPv4 rules did not match IPv4 clients | **filed 2026-10-02, closed 2026-10-03.** · `edfd99a` · [`docs/closed/158.md`](docs/closed/158.md) |
| **159** | `--host ::` was dual-stack on Linux and IPv6-only on Windows | **filed 2026-10-02, closed 2026-10-03.** · `a842f47` · [`docs/closed/159.md`](docs/closed/159.md) |
| **156** | one source could hold every connection a stream listener had | **filed 2026-10-02, closed 2026-10-03.** · `0fd0a55` · [`docs/closed/156.md`](docs/closed/156.md) |
| **151** | the chain-of-trust walk had no type, so its RFC rules lived in the async loop | **filed 2026-10-01, closed 2026-10-03.** · `2508d1b`, `3935df9`, `b8dcc95`, `d407877`, `4244af4` · [`docs/closed/151.md`](docs/closed/151.md) |
| **162** | a TLS handshake had no deadline on DoT or DoH, so a peer sending no ClientHello held a connection slot | **filed 2026-10-03, closed 2026-10-03.** · `4e9d9be` · [`docs/closed/162.md`](docs/closed/162.md) |
| **161** | a DoH connection was never closed for being idle | **filed 2026-10-03, closed 2026-10-03.** · `6f95f74`, `34a57a2` · [`docs/closed/161.md`](docs/closed/161.md) |
| **160** | `rdnsd`'s fold buffer was passed to nothing since #38, and a DNS-0x20 query allocated twice to fold | **filed 2026-10-02, closed 2026-10-03.** · `3759784` · [`docs/closed/160.md`](docs/closed/160.md) |
| **163** | a TCP or DoT peer that never read its replies held its connection, slot and the shutdown drain forever | **filed 2026-10-03, closed 2026-10-03.** · `0d0d5f2` · [`docs/closed/163.md`](docs/closed/163.md) |
| **164** | a DoQ client's packets kept an idle connection open, PINGs included | **filed 2026-10-03, closed 2026-10-03.** · `9fa0fa5` · [`docs/closed/164.md`](docs/closed/164.md) |
| **165** | DoQ answered every stream error with a stream reset and `DOQ_PROTOCOL_ERROR` | **filed 2026-10-03, closed 2026-10-04.** · `17823c4` · [`docs/closed/165.md`](docs/closed/165.md) |
| **166** | a DoQ stream answered slower than the idle timeout is lost when the client is silent | **filed 2026-10-03, closed 2026-10-04, not a defect.** · `284ff25` · [`docs/closed/166.md`](docs/closed/166.md) |
| **168** | a resolution had no time limit: 157.5 s through silent nameservers, holding a UDP permit | **filed 2026-10-04, closed 2026-10-04.** · `d4a7399`, `10edf61` · [`docs/closed/168.md`](docs/closed/168.md) |
| **169** | a flood of names under silent zones held every UDP place, from ~102 queries a second | **filed 2026-10-04, closed 2026-10-05.** · `287284c` · [`docs/closed/169.md`](docs/closed/169.md) |
| **170** | DoH allowed 200 queries per HTTP/2 connection where TCP and DoQ allow 16 | **filed 2026-10-05, closed 2026-10-05.** · `4fcfb5e` · [`docs/closed/170.md`](docs/closed/170.md) |
| **167** | `rdnsd`'s idle-timeout startup test was reset by a listener a concurrent test's child inherited | **filed 2026-10-03, closed 2026-10-05.** · `30e184f` · [`docs/closed/167.md`](docs/closed/167.md) |
| **181** | `rdnsd` gives every client the same answer: no views, no geo | **filed 2026-10-05, closed 2026-10-06, wontfix.** · [`docs/closed/181.md`](docs/closed/181.md) |
| **171** | `rdnsr` had no client access control: bound off localhost, it was an open resolver | **filed 2026-10-05, closed 2026-10-07.** · `f9716c8` · [`docs/closed/171.md`](docs/closed/171.md) |
| **173** | `rdnsr` answered NXDOMAIN for every RFC 6303 reverse zone, and nothing could override it | **filed 2026-10-05, closed 2026-10-07.** · `458734e` · [`docs/closed/173.md`](docs/closed/173.md) |
| **187** | no response was padded when the query asked for it (RFC 7830 §4 MUST) | **filed 2026-10-06, closed 2026-10-07.** · `16c43fe` · [`docs/closed/187.md`](docs/closed/187.md) |
| **186** | `rdnsr` counted no validation outcomes, and `dns_validation_errors_total` was not about DNSSEC | **filed 2026-10-06, closed 2026-10-07.** · `2c9a926` · [`docs/closed/186.md`](docs/closed/186.md) |
| **184** | stale statements in `docs/` and two code comments | **filed 2026-10-05, closed 2026-10-07.** · `0d95e3b` · [`docs/closed/184.md`](docs/closed/184.md) |
| **183** | signing with an imported RSA key was implemented and never tested | **filed 2026-10-05, closed 2026-10-07.** · `1288421` · [`docs/closed/183.md`](docs/closed/183.md) |
| **179** | `rdnsd` and `rdnsr` did not answer NSID (RFC 5001) | **filed 2026-10-05, closed 2026-10-07.** · `76b0bb8` · [`docs/closed/179.md`](docs/closed/179.md) |
| **189** | `rdnsr` could not ask its upstreams for NSID | **filed 2026-10-06, closed 2026-10-07.** · `262fe23` · [`docs/closed/189.md`](docs/closed/189.md) |
| **176** | `rdnsr` had no negative trust anchors (RFC 7646) | **filed 2026-10-05, closed 2026-10-07.** · `060f989` · [`docs/closed/176.md`](docs/closed/176.md) |
| **172** | `rdnsr` could not forward one domain and recurse the rest | **filed 2026-10-05, closed 2026-10-07.** · `c76081a` · [`docs/closed/172.md`](docs/closed/172.md) |
| **174** | `rdnsr` had no local data except through RPZ | **filed 2026-10-05, closed 2026-10-07.** · `977c0f6` · [`docs/closed/174.md`](docs/closed/174.md) |
| **191** | `rdnsr` emitted no dnstap | **filed 2026-10-07, closed 2026-10-07.** · `410adf9`, `c8810c3` · [`docs/closed/191.md`](docs/closed/191.md) |
| **193** | six RFC 6303 zones were not empty zones | **filed 2026-10-07, closed 2026-10-09.** · `736c6ae` · [`docs/closed/193.md`](docs/closed/193.md) |
| **195** | concurrent dynamic UPDATEs lost acknowledged changes | **filed 2026-10-08, closed 2026-10-09.** · `3bff6aa` · [`docs/closed/195.md`](docs/closed/195.md) |
| **196** | raw control bytes in two test literals | **filed 2026-10-08, closed 2026-10-09.** · `1738468` · [`docs/closed/196.md`](docs/closed/196.md) |
| **178** | rdnsr control socket: flush, dump, nta, reload | **filed 2026-10-05, closed 2026-10-07.** · `3fcd534` · [`docs/closed/178.md`](docs/closed/178.md) |
| **188** | Windows control channel: a named pipe | **filed 2026-10-06, closed 2026-10-07.** · `e8ebd1c` · [`docs/closed/188.md`](docs/closed/188.md) |
| **175** | DNS over TLS to forwarders | **filed 2026-10-05, closed 2026-10-07.** · `b21b5dd`, ` d8f5561` · [`docs/closed/175.md`](docs/closed/175.md) |
| **177** | Local root fallback (RFC 8806) | **filed 2026-10-05, closed 2026-10-07.** · `d30aabb` · [`docs/closed/177.md`](docs/closed/177.md) |
| **180** | KSK retirement gated on the parent's DS | **filed 2026-10-05, closed 2026-10-07.** · `4a5e544` · [`docs/closed/180.md`](docs/closed/180.md) |
| **182** | Catalog zone generated from the primary zones | **filed 2026-10-05, closed 2026-10-07.** · `eab1069` · [`docs/closed/182.md`](docs/closed/182.md) |
| **197** | comments narrated history | **filed 2026-10-08, closed 2026-10-09.** · `03500db`, `f7e27bd`, `0505311`, `f142442`, `9221737`, `e1836d5`, `3ed61c2`, `fd529a1`, `94e4307`, `5435ce3` · [`docs/closed/197.md`](docs/closed/197.md) |
| **198** | the IXFR journal was written and fsynced under the zone map's write guard | **filed 2026-10-08, closed 2026-10-10.** · `97b8e39` · [`docs/closed/198.md`](docs/closed/198.md) |
| **201** | no release pipeline; nothing was built from a tag | **filed and closed 2026-10-10.** · `8eb6ad9` · [`docs/closed/201.md`](docs/closed/201.md) |
| **202** | the interop harness ran only by hand | **filed and closed 2026-10-10.** · `c7cc513` · [`docs/closed/202.md`](docs/closed/202.md) |
| **204** | no coverage-guided fuzzing | **filed and closed 2026-10-10.** · `600b4e7` · [`docs/closed/204.md`](docs/closed/204.md) |
| **205** | no mutation testing | **filed and closed 2026-10-10.** · `5aa1b76` · [`docs/closed/205.md`](docs/closed/205.md) |
| **203** | no performance pipeline; a throughput regression failed nothing | **filed and closed 2026-10-10.** · `b799543` · [`docs/closed/203.md`](docs/closed/203.md) |
| **199** | comments exceeded the length "Writing comments" allows | **filed 2026-10-09, closed 2026-10-09.** · `e5d3540`, `9296c62`, `e3e00f3`, `5c7dead`, `374939f`, `4f52a81`, `e7a2d7f`, `19c3f83`, `375fb10`, `df25448`, `a71aea5`, `f31091f`, `473e0ad`, `8964179`, `17e09be`, `ad50676` · [`docs/closed/199.md`](docs/closed/199.md) |

**Two corrections this rewrite had to make**, recorded rather than quietly
applied (`CLAUDE.md` §11):

- **#30's row said `open` while its own "Order" section said every remaining
  item was done.** Both were written on the same page within a day of each
  other. A status held in two places disagrees eventually, which is the argument
  for this table being the only place a status lives.
- **Fourteen section headings were wrong or absent.** Eleven still said
  "filed" for work that had closed (#7, #22, #24-#32) and three carried no
  status at all (#2, #14, #16). All fourteen are corrected in
  `docs/closed/` with the original struck through, because a heading is
  the first thing read and was the last thing updated.

---

## Architecture

Why the code has the shape it has, one file per topic in
`docs/architecture/`. The API cheat sheets are
`docs/architecture/quick-reference.md`.

- [the resolver](docs/architecture/resolver.md)
- [DNSSEC](docs/architecture/dnssec.md)
- [aggressive use of validated denials (RFC 8198)](docs/architecture/aggressive-denial.md)
- [what `rdnsr` remembers](docs/architecture/rdnsr-memory.md)
- [persistence](docs/architecture/persistence.md)
- [names that never leave (RFC 6761, 6762, 6303)](docs/architecture/special-use-names.md)
- [following a trust anchor (RFC 5011)](docs/architecture/trust-anchor-rollover.md)
- [incremental transfer (RFC 1995)](docs/architecture/ixfr.md)
- [the secondary role](docs/architecture/secondary.md)
- [signing a zone](docs/architecture/signing.md)
- [writing a zone back out](docs/architecture/zone-writing.md)
- [zone storage](docs/architecture/zone-storage.md)
- [amplification](docs/architecture/amplification.md)
- [NOTIFY](docs/architecture/notify.md)
- [TSIG](docs/architecture/tsig.md)
- [zone transfer](docs/architecture/zone-transfer.md)
- [one process per server](docs/architecture/one-process-per-server.md)
- [DNS over TCP (both daemons)](docs/architecture/tcp.md)
- [why `rdnsr` is separate from `rdnsd`](docs/architecture/why-rdnsr-is-separate.md)
