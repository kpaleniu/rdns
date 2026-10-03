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

**#166 and #167**, as of 2026-10-04, each `docs/issues/NNN.md`; #165 closed
that day, #151 and #155-#164 on 2026-10-03, #150, #152, #153 and #154 on 2026-10-02. #160 was
found closing #150, #161 closing #155, #162 triaging #161, #163 grilling it,
#164 triaging #163, #165 grilling #164, and #166 and #167 closing it.

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
| **1** | recursor follow-ups | done |
| **2** | DNSSEC follow-ups | done |
| **3** | NSEC3 salt and iterations | done |
| **4** | zone lookup | done |
| **5** | smaller items: AXFR, TSIG, NOTIFY, IXFR, amplification, negative caching, `$INCLUDE`, TXT framing | done. No section of its own; the entries are in `docs/closed/log.md`'s "Done so far" |
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
| **21** | the deliberate RFC deviations and the not-implemented list | **filed 2026-08-03, closed 2026-09-29, wontfix.** Decisions, not a queue; every row re-checked against the code the day it closed. A row taken up gets its own number, as #34, #35, #36, #42 and #44f did. See `docs/closed/021.md` |
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
| **38** | a structural review, and what it left | **filed and closed 2026-09-09 → 2026-09-10**: three fixes in the filing commits and five sub-items after them, 38e's cross-crate half decided against rather than done. **Nothing filed was a defect**; the one defect the review turned up was in the fixed half — a DO bit dropped by three reply paths across both daemons, against `rdnsd/src/answer.rs`, which mirrored it. 38d's `rdnsd` half is what filed #39. |
| **39** | `rdnsd` answers through two dispatchers | **filed and closed 2026-09-10 → 2026-09-11**, five items. 39a was the defect: a TSIG-rejected request counted as received over TCP and not over UDP, because the two prologues had drifted. 39b built all three shapes before keeping one, and the two it declined are the argument — a trait that had to name the type it existed to hide, and a `transport` plus `out` pair that could disagree with itself. |
| **41** | nothing capped the UDP response, and the sizes were hardcoded | **filed and closed 2026-09-11**, four items, none of them a live defect. 41b's measurement came before its fix and is `rdnsd/src/response_size.rs`; 41a and 41b became one type, `rdns::UdpSizes`, whose `reply_ceiling` cannot be asked without the `min`. The hardcode had three instances and not the two the filing named — 41c, where the third was also a receive buffer, and where Unbound's 64 KiB was the obvious answer and the wrong one: `--max-inflight-udp` multiplies it by 1024. 41d found RFC 8945 §5.3 had already written the remedy the row guessed at. Nothing filed on the way out. |
| **42** | the three encrypted transports | **filed 2026-09-11, closed 2026-09-12**, three stages in the order filed. Every dependency number in the filing held — **117 packages for all three**, against the predicted 118, the difference being one `log` this build turns off. The architectural prediction held too: DoT and DoQ carry RFC 1035 §4.2.2's framing unchanged, so `tcp::serve_one` and `Handler` answer on all three transports without knowing which. What the filing got wrong was the size of the metrics fold: 25 lines of code, not ~58, because it counted what `hyper` replaces and not what it asks for back. One certificate store serves all three and one SIGHUP renews it. Image cost, which the filing named as unmeasured: **+1.44 MiB on a 30 MiB image**, of which `hyper` is 0.54 |
| **48** | a catalog's `group` property is read and not acted on | **filed 2026-09-12, closed 2026-09-13.** `[zones."$CATZ".groups."value"]` with a `masters` list, per catalog zone as RFC 9432 §4.3.2 asks. All three things the filing said to settle were settled as it proposed; what it did not see is what a group change costs — the copy on disk came from the old master, so the zone stops being *served* until the new one answers, which is the rule every secondary gets. Two tests changed, both encoding the sidecar's format rather than a behaviour |
| **49** | nothing on the control socket says a zone came from a catalog | **filed 2026-09-12, closed 2026-09-13.** Both shapes the filing drew were built and both kept: they answer different questions, and only the second — `rdnsctl catalog` — can report a member the server *refused*, which has no zone and so no row in `status`. The design decision the filing named was the refusal list; it is bounded at 16 with the total beside it and rebuilt every reconcile, since a refusal is a property of the catalog as it stands |
| **45** | what an ISP would find missing in `rdnsr` | **filed 2026-09-11, closed 2026-09-13**, five rows in one day. Four were absences and the fifth was a decision, answered **no**. Each of the four cost more than its row said, and in the same way: the *arithmetic* was small and where the decision belonged was not. RPZ's lookup is `Zone::locate` on a trigger name, so RFC 1034 §4.3.3's wildcard rule is the RPZ wildcard rule — but the delivery its row called the pleasing part turned out to live in `rdnsd` (#57), and two of five trigger types need a delegation path the resolver does not hand back (#56). serve-stale is one comparison, and the two eviction paths that swept the window were found by tests rather than by reading. Prefetch is a tenth of a TTL, and the part that matters is handing the obligation to exactly one client. DNS64 is RFC 6052 §2.2's table, and the work was deciding which of six answer paths may synthesize. Left behind: **#56**, **#57**, **#58** |
| **46** | `rdnsd` could not sign a NOTIFY | **filed and closed 2026-09-12**, three items, all of them live. 46a: `--also-notify` took an address and nothing else, so a secondary whose notify ACL names a key refused every notification — measured against NSD and Knot, both. 46b: that refusal was logged `acknowledged (Refused)` at INFO, which is a permanently broken notification path with nothing in a failed state. 46c was found while fixing the other two and was the worst of the three: `[zones."x"].also-notify` was parsed into `PerZone::notify` and read by nothing, with two `docs/spec/` files documenting it as working. `--secondary` and `--also-notify` are one parser now (`rdns::endpoint`), which is why 46a existed at all |
| **43** | nothing here had ever answered another implementation | **filed 2026-09-11, closed 2026-09-12.** `tests/interop/` — one `docker compose` network, `run.sh all`. 112 assertions against BIND 9.20.27, Knot 3.6.0, NSD 4.12.0, Unbound 1.23.1 and ldns 1.8.4; 0 failures. **Neither of the two things the filing predicted happened**: the IXFR is a real delta in both directions and every NSEC3 shape validates. Found one gap, in NOTIFY, which no row had named — **#46**. Three of the first five apparent findings were the harness, and the section says what each was, because that ratio is the lesson |
| **50** | verifying a signed zone at load was quadratic in the zone | **filed and closed 2026-09-12**, found by 44c's measurement rather than by reading the code. `validate_response` collected every DNSKEY and every RRSIG in the zone on every call and `verify_rrset` then scanned what it collected, so `verify_zones` — which runs at startup, on SIGHUP, on `rdnsctl reload`, on the re-signing tick and inside `--check-config` — cost the square of the zone. **20,006 RRsets: 112.68 s before, 0.65 s after**, and a million-record zone goes from days of arithmetic to a measured 76 s. The fix is a `ZoneKeys` the caller hoists and a signature lookup through the zone's own owner index; the guard is an allocation count (34 either side of a fifty-fold zone, 217 against 6,101 with the scan) plus a ratio test in `rdnsd`. Filed **#53** on the way out |
| **53** | a zone was verified at load even when this server had just signed it | **filed 2026-09-12, closed 2026-09-13**, left behind by #50 and only visible once #50 stopped hiding it. The row proposed "verify what we signed once, at startup"; what landed is **once per zone per set of signing keys**, which costs the same and has neither of that rule's two holes — a zone appearing after a SIGHUP was never at a startup, and #44f made a key crossing its Activate change the output with the zone file unchanged, so a rollover publishes signatures nothing has checked. `ZoneSigning::apply` returns what it signed with which key tags; the proof is recorded **after** the zone verifies, because recording first lets the next reload install what this one refused (§4), and that is a test. Startup and `--check-config` still check everything. Worth 76 s of a re-signing tick on a million-record zone, asserted as a count (`Checked { zones: 0, rrsets: 0, skipped: 1 }`) rather than a clock. The number the row said would decide it — how long a fleet's tick may take — was not needed. Nothing filed on the way out |
| **51** | XoT authorized its client by ACL and TSIG, never by certificate | **filed 2026-09-12, closed 2026-09-13**, the client half — which is the gap the row was filed for: a primary demanding mTLS could not be replicated from. `--transfer-tls-cert`/`--transfer-tls-key`, both or neither and only with `--transfer-tls-ca`. Two things the row did not have: rustls runs `keys_match` inside `with_client_auth_cert`, so a mismatched pair is a startup error for free; and `XotTrust::anchor_count` had **no callers** — written "for the startup banner" and the banner never added (§18), which is where "a certificate is loaded" is now said, since a certificate is offered only if a master asks and "mTLS is in force" is not a claim this end can make. One PEM loader now, `rdns::tls_identity::TlsIdentity`, which is what `rdns-transport`'s `read_certs`/`read_key` became (§7). The negative control corrected the guess (§19): a master that demands a certificate and gets none fails on the **read**, not the handshake — TLS 1.3 lets the client finish first — so what the operator sees is `CertificateRequired` under the transfer. Filed **#59** (the server half: #54's plumbing under #16's question) and **#60** |
| **54** | a dispatcher could not say which encrypted transport a message arrived on | **filed 2026-09-12, closed 2026-09-13**, taken ahead of #59 because it is its plumbing. `validation::Arrival` on `Handler::handle`, `tcp::serve_one` and `Wire::Framed`; `Privacy` is derived from it and dnstap now names all five transports. **All three shapes were built** (§19) and the decision turned on none of the things that were argued: A is not a shape at all — clippy says "too many arguments (8/7)" at `serve_one`, exactly as the row predicted; B and C are the same **2** bytes, within ten lines of diff, and the same 1,121 tests. What decided it is that B compiles `Arrival { privacy: Tls13, protocol: Tcp }` — a plain TCP connection claiming to have hidden everything, which is the value `answer_transfer` reads to let a zone leave the building. **And the row's own numbers did not reproduce**: it claimed 30 `Privacy` sites of which 19 were `Privacy::Clear`; re-counted on the commit before the fix, 44 across 8 files of which 10. Nothing had touched `Privacy` in between. Nothing filed on the way out |
| **55** | nothing generated CDS or CDNSKEY, so a KSK rollover still needed a human | **filed 2026-09-12, closed 2026-09-13**, and the row's premise was wrong where it was most confident: "the gap is *generation*, not carriage" — an operator writing `CDS` by hand got *unsupported record type "CDS"*, and only RFC 3597's `TYPE59` form parsed. One `parse_zone_file` call settled it (§4). Three halves, all done. **Carriage**: both types named, one `ParsedRecord` arm each on the SVCB/HTTPS precedent, an `rtype` field across **19 sites** counted before one was edited. **Generation**: `SyncPublish`/`SyncDelete` per key, BIND's `dnssec-settime -P sync` field names, which dodges the row's "near future is a policy" problem and says the truer thing — a rollover step must not ask a registrar to act. **Signing**, the one that mattered: RFC 7344 §4.1 needs a key in both the DNSKEY *and* the DS RRsets, and `sign_everything` would have used the ZSK, which nothing downstream would report because the RRset verifies fine against the zone's own keys. RFC 8078 §4's algorithm-0 record is never generated and a zone carrying one beside a sync window is a failed run. Also closed a hole in **#53**: a `SyncPublish` crossing changes the output without changing the signing key set. dnspython validates both RRsets off a live `rdnsd` and agrees on the digest. Nothing filed on the way out |
| **56** | an RPZ's NSDNAME and NSIP triggers were counted and not enforced | **filed and closed 2026-09-13**, left behind by 45a. The callback the row preferred is what landed — `resolver::NameserverPolicy`, one method, asked at every delegation, refusing with `ResolveError::PolicyStopped` so the *caller* supplies the answer it recorded. The row's second question had a two-part answer and the part it worried about was the sound one: a stopped resolution caches nothing, so the block holds for every client, and `rdnsr` loads every `--rpz` file before a socket binds. **What was wrong was the delegation cache** — `resolve_from_root` starts at the deepest zone already known, so a policy asked only at referrals was in force for the client that walked the chain and nobody after; `CachedDelegation` keeps the referral's NS names now and the start point is offered like any other delegation. `rpz-passthru` at a delegation does not stop the walk; a refused one is not cached; a prefetch is policed and the RFC 5011 probe deliberately is not. The end-to-end test's control is its value: the same fixture with the rule pointed elsewhere is a SERVFAIL after a 1.02 s timeout. Nothing filed on the way out |
| **40** | the internal APIs, asked whether they fit each other | **filed and closed 2026-09-10 → 2026-09-11**, six items. A pass over the *joints* rather than the modules, filed as "nothing here is a live defect" — and two of the six turned out to carry one. 40f's measurement found the UDP request cap refusing what every reply's OPT advertises, so a legitimate signed UPDATE was dropped in silence; 40d's second half deleted six silent `continue`s by typing a map key. 40b's filing was wrong and its row says why. Filed **#41** on the way out. |
| **52** | a rate-limit test is a coin toss at a second boundary | **filed and closed 2026-09-12**, one commit. Not a defect in the server, and the filing undercounted it by 23: the shape is a test that reads the wall clock at a limiter call, and there were **43 such call sites across 24 tests**, six of them assertions a refill actually breaks. Both buckets refill by whole seconds, so the verdict depended on whether two reads straddled one. 41 sites needed nothing but one `let now` per test, because `should_allow` has taken the instant as a parameter since #28a; the two that read the clock inside the loop under test — `tcp::serve`'s per-connection charge and `rdnsr`'s UDP loop — got `rdns::clock::Clock` on `ServeContext`. The test now asserts the refill as well as the refusal, which is the half that says the connection was charged rather than never admitted |
| **47** | a NOTIFY reply carried no OPT record | **filed and closed 2026-09-12**, one commit, and it was a defect after all: the row read RFC 6891 §6.1.1 as "asks for" where it is "if an OPT record is present in a received **request**, compliant responders MUST include an OPT record in their respective responses" — a NOTIFY is a request. Counting the shape (§18) found a second site and a second MUST: `transfer::Envelopes` built the first AXFR envelope's OPT from `has_edns()` and a fresh `Edns`, which drops DO, against RFC 3225 §3's unconditional "the DO bit of the query MUST be copied in the response". Nothing tested either. The three NOTIFY refusals now carry three different EDEs, because "you are not one of my masters" and "I am that zone's primary" are one RCODE and two operator problems. `ClientEdns::mirror_with` became total on the way, so the `Err` all three callers answered identically is one doc comment rather than four. The EDE half is a reading rather than a quotation and the peers were asked: BIND 9.20 and Knot 3.6 mirror the OPT and DO and send no EDE, NSD 4.12 answers NXDOMAIN with QDCOUNT=0 and no OPT. Nine new assertions in the interop harness, 29 passed 0 failed in 43e |
| **44** | what an operator would find missing in `rdnsd` | **filed 2026-09-11, closed in full 2026-09-12**, seven rows: catalog zones, EDE, the scale measurement, XoT, multi-signer, rollover and dnstap. Five numbers filed on the way out — #47, #48, #49, #50, #51, #54, #55 — and **0 packages** added by the lot, dnstap's two wire formats included. Every row's closing note says the same thing in its own words: the filing was right about what was missing and wrong about where the work was. 44a missed that provisioning is a diff; 44b's "small" cost a type at 24 sites; 44d's "cheap after 42a" described the half already done; 44e's premise was refuted by one test; 44f's ZSK half needed four numbers in a file and no state machine. Only 44c came out the size it was filed as, and it is the one that found a live defect (**#50**). The preamble's "none of these is a defect" did not survive either: #50 came out of 44c, and #47 — filed by 44b as not a defect — closed carrying two MUSTs |
| **60** | a string continuation flattened into spaces was an operator-facing defect | **filed 2026-09-13, closed 2026-09-14.** 19 lost `\` continuations put back and a test that will not let a twentieth in. `946899e` |
| **61** | a million-rule reload spent its time building the index, not parsing | **filed and closed 2026-09-14.** The zone index built once, and the file no longer copied to read it. `6ced88c` |
| **62** | three unbounded-input traps behind an assumption nothing enforced | **filed and closed 2026-09-14.** RPZ address triggers answered by binary search over `rpz::IpIndex` and indexed with a set; a zone file's apex moved once, not per `$ORIGIN`. `93b3cb0`, `c222246`, `2f70ba1` |
| **65** | every load re-signed every zone from scratch | **filed and closed 2026-09-14**, out of 64e. `ZoneSigning::apply` signed unconditionally, so a SIGHUP, an `rdnsctl reload` or a catalog change cost a full sign of every signed zone — 27.6 s at a million records — and moved the RDATA of every RRSIG, which is the whole zone in the next IXFR delta. **The four shapes were built and the recommended one was declined** (§19, #40a's precedent again). What landed is A, keyed on the trigger: the re-signing timer reloads *in order to* refresh, so it is the one reload that may carry nothing forward, and the other two carry everything whose RRset did not move — 9.7 s against 27.6, still 53.6% saved when a tenth of the zone changes (65b). **B is declined on a measurement**: the expiry spread is a fifth of the validity and the re-signing interval a third, so every signature crosses any refresh threshold in the same tick — 0 or all 126 of a fixture's RRSIGs, never between — and the only threshold that saves work hands the refreshing run a signature with four tenths of an interval left, against the 1.4 §8 asks for. The patch was reverted and the finding kept as a tripwire on the two constants. C moved to **#64b** and then, when 64b closed without reaching the reload path, to **#64f**. The prerequisite the row called plumbing was one four-line method: `Zones::snapshot_all` |
| **63** | `rdnsr` had 39 flags and no config file | **filed 2026-09-14, closed 2026-09-15**, ten rows, filed out of 57d because a prerequisite named in prose is one nobody schedules (§18). 63a answered the split question with the compiler rather than a line count — 18 escaping items of 84 `pub`s, and 63g then measured that `rdnsr` would name **0** of them — so the module stayed in `rdnsd` and what is shared is one macro. 63h built all three shapes and kept the two declined ones as branches: the shared struct is out because `#[serde(flatten)]` makes serde buffer the table, costing every `[server]` typo its line number and its expected-key list in `rdnsd`'s existing file too. On the way, 63e found 16 defaults written twice with nothing comparing them, 63f the same bare-`pub` sweep for the `cfg(unix)` file Windows cannot compile, and 63i the one flag of 35 not refused beside `--config`. **63j is what the file existed for**: `[[rpz.feeds]]`, a policy per feed, which costs the match path nothing because `PolicyZone` has carried one since 45a. `rdnsr --check-config` closed with it |
| **66** | `rdnsc` could not write what it transferred | **filed and closed 2026-09-15.** A transfer printed as a zone file, and TSIG in its own crate, `rdns-tsig`. `c6ee084`, `ca19761`, `e26a479` |
| **67** | the crate split, re-measured once a small binary took crypto | **filed and closed 2026-09-15.** 67a-c took the free set from 9 of 41 to 23; 67e declined with its numbers; 67f-g deleted dead API. `983e4fe`, `8f64072`, `7187af4`, `c0238ff` |
| **64** | one dynamic UPDATE was five O(zone) passes | **filed 2026-09-14, closed 2026-09-16**, seven rows, and it was filed with the measurement that refuted the fix it was going to propose (§19). 64a: a whole-zone clone nobody read, three instances not one, fixed in the type. 64b: read the file's bytes every time, parse them only when they are not the bytes this server last wrote — 38% off an unsigned update, and its headline number *did not reproduce* because one `--ignored` filter selected two million-record benchmarks and libtest ran them at once. 64d: signing is 88% of a signed update, and the measurement that could have refuted it — `carried` — refuted the *explanation* instead: exactly four RRSIGs are made fresh at any zone size. 64e: the two structures the split named, three shapes built, −14%. 64f: a reload keeps the zone it is serving for a file nobody touched, 11.4 s to 39 ms, on the condition `ProvenSigning` already computes. **64c is the one declined**: its 42% was more than half serializer — RFC 3597's hex form built for every record and thrown away — and `to_string` fell 636 ms to 250 with the file still the authority, which leaves the checkpoint design buying 387 ms of a 1 335 ms update and 4% of a signed one. 64g, the one 64e did not take, closed the same day #64 did: the type change it was filed as too big for is a default type parameter and **zero** of `Rrset::new`'s 43 call sites, it takes the named pass down 25% — and the total does not move, because the clone it removes was buying the signing loop its locality. Landed on the allocation count (593 -> 566 on an eight-record zone) and said so |
| **59** | nothing here demanded a client certificate for a transfer | **filed 2026-09-13, closed 2026-09-16**, the server half of #51 and RFC 9103 §7.5's other method — the one the section says to prefer. The shape the row named is what landed: an optional verifier, so the same listener still answers a DoT stub with no certificate, and the transfer path refusing what arrived without one. **Neither of the two identity mappings it proposed survived**: a certificate standing for a TSIG key's scope would need both credentials, and a hand-matched subject would be the X.509 parser #42a declined. What landed is the subject *alternative* name checked by `webpki` — the same code that verified the chain, already in the lock, **0 packages** — with `--allow-transfer-cert name[:zones]` in `--tsig-key`'s spelling. Authentication and authorization stay apart (#16): a second certificate from the same CA transfers nothing until it is listed. `ZoneScope` is now one type for both credentials, and `Arrival` carries the certificate, which is what #54's shape was built for — `Arrival::Tcp` cannot carry one. The row's own §19 answer is unchanged and still right: no peer exists that will not transfer over TSIG |
| **70** | the metrics endpoint did not enforce RFC 9112 §3.2, and its header said it did | **filed and closed 2026-09-16**, out of #68. Both of the header's claims about hyper were estimates of somebody else's code and both were wrong — no `Host` was **200**, not 400, and an over-long request line is **414 past 64 KiB**, not 431 past 8 KB — and four tests in that same file had disproved the first on the day it was written. Filed as a decision rather than a defect and taken by the owner: `bad_host` now answers 400 to all **three** of §3.2's MUSTs, which the row had read as one, and hyper answered 200 to every one of them. The count was wrong too — "four tests" was six tests and eleven requests (§18). The probe it costs is paid back in the refusal's body: §3.2 exempts HTTP/1.0, and `curl`, Prometheus and CI's own probes all send a `Host` |
| **57** | a policy zone arrived as a file somebody else wrote, not as a transfer | **filed 2026-09-13, closed 2026-09-16**, five rows, left behind by 45a — and the delivery half needed no code in `rdnsd` at all: `announce_transfer` had notified every `--also-notify` peer after every transfer since it was written, and what was missing was `rdnsr`'s ear (57c). 57a's reload found a resolver with `--rpz` and no DoT that had no reload task at all; 57b measured the reload *on* a worker and a one-core resolver answering nothing for 2.7 s. 57d built both shapes and was decided by neither's install cost: A keeps the file, so a restart begins with yesterday's rules. 57e is the one whose own measurement refuted it — IXFR was **slower than AXFR** here, 1 485 ms against 1 372 at a million rules, because applying forty records built a key per record of the base; and the bigger miss was that a refresh had no SOA probe at all, so an unchanged feed cost a transfer and a reload every REFRESH. Both daemons share `xfr::refresh_zone` now (§7). **#71** is what is left, and it is neither the wire nor the format — and every figure in this row was taken under the libtest contention #71 found, so they are the shape and not the clock |
| **69** | four accept loops ended on any error, where the UDP side had a helper | **filed and closed 2026-09-16**, out of #68. Filed with no remedy on purpose (§18), and both missing measurements were taken the same day — which reversed the reason. **The remote provocation does not exist**: four `SO_LINGER 0` resets before the accept come back as `Ok` on Windows and on Linux, so §4's *remote* kill switch does not apply. **Descriptor exhaustion does, and needs nobody**: at `ulimit -n`, `accept` returns `EMFILE`, `Uncategorized`/raw 24, invisible to every portable kind — and both daemons' `JoinSet` ends the process when its first task ends, so `accepted?` turned a self-clearing condition into a whole-server outage across every transport. Windows could not be made to reach it (100 000 handles, no failure). Provoked before and after against a real `tcp::serve`: the old code's next write is a reset, the new one answers. One shared `survive_accept_error` at all four sites — retry the aborted kinds, log and back off 100 ms on exhaustion, still fatal otherwise |
| **71** | applying a forty-record change was sized by the zone, twice over | **filed 2026-09-16, closed 2026-09-19**, seven rows, out of 57e — which had taken the *wire* down to what changed and left everything after it O(the zone). **801 ms to 44.3** for a forty-rule change at a million rules. 71b: a reload keeps every feed whose file did not move. 71c: three of four zone rebuilds never got #61b's `reserve`, which was over half of what 71a was filed at — a row filed as a type problem whose larger half was one line. 71d: the index keyed every name on a `Box<[u8]>` because a `HashMap` reaches its key only through `Borrow`, an artifact of the collection and not of `Name`. 71f: the install wrote the file and then *parsed it back*, 613 ms of re-deriving a zone the process was holding, under a comment calling it a trade — and the assertion cited as evidence compared two `usize`s. **71a**: not the tombstones it named — a count of direct children makes a name removable without turning a NODATA into an NXDOMAIN, and `swap_remove` leaves exactly one stale position. **71e**: two arenas, so a copy is a memcpy and six allocations rather than two million; `Zone::clone` 97.6 ms to 18.7, the whole answer path −6.1% and the lookup alone +5.4%. Two rows had their order the wrong way round (71a said to take 71e first; it was the reverse) and both blast-radius counts were measured by deleting an API rather than replacing it. Filed **#72** on the way out |
| **72** | a zone's arena was filled from what the caller had just allocated | **filed and closed 2026-09-19**, three passes, out of 71e. Filed at two allocations a record and the copy between them; there were **seven**, and the two it named were the smallest — the largest was one line of `Zone::add_record` itself, folding an index key `intern` copies into its own arena a moment later. A million-record zone of A records now parses with **no heap allocation per record at all**, **480 ns a record to ~263** (`rdns/tests/scale.rs`), and a mixed-type one 535 to 438. `Zone::add` and `Zone::add_parsed` are the borrowed and the not-yet-encoded doors beside `add_record`; `Name::absolutized_in` settles a zone file's three spellings of an owner name in one place; `RdataArena::push_parsed` encodes into the arena under the same argument `RecordData::from_parsed` already stands on. **72a** was filed as §7 and was §4: the two field lists `rdata_from_fields` took were `tokens` and `tokens.iter().map(Cow::as_ref)`, the same strings by construction, under a comment saying one kept its quotes. **72b** went to zero rather than the one it predicted, and its first version moved an *exact* count **up** — `Vec` takes a byte vector's capacity to 8 whatever it holds, so the shrink to a `Box` cost a reallocation per record on the **message** path; sized from the RDLENGTH that arrived, it is 15 again. An exact count is what caught it. Two refutations recorded on the way: none of the three other build sites the row named gains from the borrowed door, and the signer's seven sites stay, because signing is ~27 µs a record |
| **73** | a denial outlived the SOA beside it | **filed and closed 2026-09-19**, `35b1e8f`, out of an architecture review. RFC 9077 §3: an NSEC or NSEC3 TTL is the *lesser* of the SOA's MINIMUM and the SOA record's own TTL, and the signer used MINIMUM alone. RFC 4034 §4.1.1's older "same as MINIMUM" predates aggressive use, under which the denial's own TTL is how long a resolver goes on synthesizing that "no" — and this tree implements that other half (`rdns::nsec_cache`). Measured on `$TTL 300` with `minimum 3600`: SOA 300, NSEC **3600**, its RRSIG **3600**; all 300 after. The fix is one `.min(soa_ttl)`, on a value bound six lines above and used for the DNSKEY TTL only. **Why the suite never saw it**: every fixture is `$TTL 3600` with `minimum 300`, the direction where the `min` is invisible — and `rdnsd/src/answer.rs` asserts "capped at MINIMUM, not the `$TTL`", which is right only because 300 < 3600. RFC 9077 is cited nowhere else in the tree. Left **77a** |
| **74** | `--check-config` did not name DoH | **filed and closed 2026-09-19**, `20b8dc8`. The dry run matched on `--tls-listen` and `--quic-listen`, so a DoH-only server was told "encrypted transports disabled" by the one command whose whole job is to be believed before a restart — while the `encrypted` predicate eighteen lines above, which decides whether to read the certificate at all, has named all three since DoH landed. Provoked rather than read (§4). **Why the second copy existed**: `describe_encrypted` had all three right and took a `TlsPolicy`, which is not built until after the dry run returns — a function that is correct and unreachable is how §7's second copy gets written. It takes the three addresses now. ~~`--check-config`'s output still has no test at all, which is how a hand-written banner stayed wrong~~ **It has one since #90** (2026-09-20), asserting the line rather than the exit status, for exactly that reason |
| **75** | two of three answering paths returned past the epilogue | **filed and closed 2026-09-19**, `74019de`. `record_dnstap` was reachable only through `finish`, and the transfer and UPDATE branches `return`ed above it — so a dnstap capture held neither, while `--dnstap` says "every answered request" and `MessageType::UpdateQuery`/`UpdateResponse` were arms nothing could reach. §7's named shape, and this file's second instance of it after the NOTIMP branch that returned past `make_response`'s OPT mirroring; the tell here was cheaper, because the unreachable arms had been *written*. `finish` returns what it sent, `answer` has one tail, and a serialization failure joins them for the reason a dropped reply already did. A transfer records the query alone: no one envelope is the reply. Left **77b**, ~~which is that there is no test~~ **closed the same day**: a query, an UPDATE and a transfer attempt down one connection, **3 data frames against 1** with this tail reverted — so the pre-#75 shape drops two of three rather than capturing nothing, which is what the row had guessed |
| **76** | `ScratchDir` existed three times | **filed and closed 2026-09-19**, `ab2ae3b`. `rdns-core::testutil` is `pub` rather than `#[cfg(test)]` for one stated purpose — "the choice was this or a second `ScratchDir`, which is the thing this module exists to have stopped" — and both binaries wrote one anyway, each citing the other, on a premise that stopped being true at #66c. `rdnsd` carried both at once: `dispatch.rs` already reached for the shared one. 57 lines deleted, 9 added, no behaviour. What it is worth is not the lines: §7 says the reason is what stops the next copy, and here the reason was copied along with the code and went on justifying it after it had expired |
| **77** | what #73 and #75 left behind | **filed 2026-09-19, closed 2026-09-20**, `1a0422c` and `2d72c4c`. **77b**: the test #75 landed without — a query, an UPDATE and a transfer attempt down one connection, **3 data frames against 1** with that tail reverted, so the old shape dropped two of three rather than capturing nothing, which is what the row had guessed. **77a**: the survey the row asked for, and it did not decide what the row expected. Knot fixes it in the signer ("TTL of *generated* NSEC(3) records"), PowerDNS in its own signing, NSD has no entry at all because it never signs, and BIND cites 9077 nowhere — while RFC 9077 §§3.1-3.3 each put the MUST on the TTL "that is returned" and §4 addresses "signers **and** DNS servers". The field and the specification disagree; `rdnsd` is both, so a zone it did not sign reaches the same answer path as one it did, and the cap is taken there too. Counted rather than timed: the NXDOMAIN path takes the same apex lookups as before, the two DO-only paths take one more each, and no benchmark covers a signed negative answer |
| **85** | the library installed the process's log subscriber | **filed and closed 2026-09-20**, out of a second architecture review. `rdns::logging::init` chose a global subscriber on its caller's behalf, against a rule two files state — the workspace manifest's `tracing` entry ("the library only emits; the binaries choose where it goes") and `rdns-transport`'s own header. Moved verbatim to `rdns_transport::logging`, the crate whose only consumers are the two daemons, so there is still one copy and not one per binary (§7). The refuting measurement was taken first and **narrowed the claim**: the seven packages this drops from `rdns` (55 → **48**) are off a fresh build's critical path — all seven finish by 7.87 s of a 21.08 s build whose path is `rdns` then `rdnsd` — and `Cargo.lock` keeps every one of them, because both daemons need the subscriber wherever it lives. So it buys `cargo build -p rdns` and the boundary, not workspace build time |
| **86** | two error enums sat in the crate that could not name them | **filed and closed 2026-09-20**, out of the same review. `DnssecError` and `BrokenCatalog` were defined in `rdns-core` and named by no module in it — 100 of that file's 264 lines, in the crate `rdnsctl` links alone as "the DNS wire format". Moved to `rdns::error` beside `TransferError`, which is there for the reason written at the top of that file; nothing downstream changed, because `pub use rdns_core::error::*` already spelled both paths the same. The refuting measurement removed a third of the finding before any edit: `ZoneError` looks identical and **must stay**, since `rdns-present` returns it and does not depend on `rdns`, so the move would need a cycle. That reason was written down nowhere and is now on the enum |
| **91** | both CI jobs no local `cargo` run covers were red | **filed and closed 2026-09-20**, found while checking a README sentence about dependency counts rather than by a review. `image` failed with `failed to read /src/rdns-present/Cargo.toml` — character for character #31's failure, with the #66c/#67 crates in place of the #31 ones, and `.dockerignore` held the same list a second time and was stale the same way. `deny` failed all three of advisories, bans and licences, none of which had ever been in the graph before `rustls` was: RUSTSEC-2026-0285 (fixed by its own remedy, `cargo update -p rustls`), `subtle`'s BSD-3-Clause (added, per that file's policy of listing what the graph reaches), and four duplicate versions — half of them **ours**, `rand` 0.8 against `quinn-proto`'s 0.10, four lines to collapse and `Cargo.lock` 218 → **214** with `getrandom` going too. Left: the RustCrypto 0.11 migration that would collapse `cpufeatures`, which is a `digest` version bump and not four lines |
| **87** | the UDP request path read the wall clock, not `ServeContext`'s | **filed and closed 2026-09-20**. #52 made `Clock` the seam and recorded its sweep as "the four accept loops read `ctx.clock.now()`"; two request-path sites are neither an accept loop nor `rdnsr`'s UDP loop, so the criterion did not reach them. Filed as latent — `Clock::System` *is* `current_unix_timestamp` — and that was right about production and wrong about testability: TSIG compares the server's instant against one the client chose, with RFC 8945 §5.2.3's 300-second fudge, so a clock the loop does not read is **visible on the wire**. Two tests, each checked by reverting the line it is about: the UDP loop answers NOTAUTH, and a refused UPDATE's TSIG reads `BadTime`. The fix is a type rather than two careful call sites (§17): threading `now` into `signed_error` reached eight arguments, which clippy refuses at seven, and `Refused { msg, ip, now, max_len }` is the four values all twenty sites already passed together. Left **#92**, the twelve reads outside any request path, with no remedy named because the obvious one is not obviously right |
| **88** | nothing measured `rdnsr`'s answer path | **filed and closed 2026-09-20**. Every allocation assertion and every benchmark lived in `rdns` and measured the *authoritative* path, so "the two daemons build a reply two ways" was an observation nobody could price — #45a had already written the sentence in prose, which §18 says is a number. One cache hit is **13 allocations**, identical on Windows and Linux and across `--test-threads` 1-3, and attributed rather than recorded (§10): 2 parse, 3 serialize — `rdns`'s own two numbers, measured again rather than quoted — and **8** for the cache lookup, the copy out of it and the message. So the two daemons differ by the copy, not by the writing: `ResponseWriter` is 0 with a held buffer and 3 without, `rdnsr`'s serialization is 3. A second test asks §10's ratio question instead of a floor and the 201st hit costs what the first did, so nothing is quadratic in how often it is asked. **The measurement was filed to decide whether to touch `handle_query`'s 432 lines, and it decided no.** Lives in `rdnsr/src/allocations.rs` rather than a `tests/` file, because a binary cannot be reached from one without a `lib.rs` and a handful of `pub`s (#82b's ratchet) — and §10's reason for the separate file is answered by the tally being per-thread, which is what `rdns`'s own file had to invent when the separate file proved neither necessary nor sufficient. That tally moved to `rdns_core::testutil::Counting<A>` rather than being written twice (§7); all 22 of `rdns`'s counts are byte-identical across the move |
| **89** | a moved module left its doc comment on the next one | **filed and closed 2026-09-20**, and it is **#79c** filed a second time a day later. `e26a479` (#66c) moved `rdns/src/testutil.rs` to `rdns-core` and left `/// Scratch directories, for tests only.` attached to the `pub mod tls_identity;` below it, where it rendered on the crate index. `cargo doc` cannot catch a doc comment that is wrong rather than broken, and #20 had already written the remedy as prose ("after any move, grep the seam for an orphaned `///`"), so nobody ran it. Deleted, and the grep is now `rdns/tests/module_doc_comments.rs`: a `///` on a `mod X;` that shares no content word with the module's name or the first paragraph of its own `//!`. **Weak on purpose** — the seven that agree measure 4, 1, 4, 5, 2, 1 and 4 shared words against the orphan's 0, so a threshold of two would flag `mod eviction` (which agrees only through its own name) and `mod dispatch`. The one recursive `.rs` walk in the tree moved to `rdns_core::testutil` rather than being written a second time (§7), and both scans assert on what it hands back. It reads source as data, so it covers `rdnsd/src/control.rs` on Windows, where that file never compiles |
| **79** | claims and code that outlived each other | **filed 2026-09-19, closed 2026-09-20**, five rows. **79a**: six dead `pub fn`, not four — a sweep of the workspace's 713 `pub fn` definitions finds four, and misses `Nat64Prefix::bits` and `TransferError::refused` because a string literal and an unrelated struct field carry those words, which is #82b's point about a name-based criterion from the other side. Two of the six were not dead code: `Rtype::is_meta` is the RFC-citing copy of a predicate `update.rs`'s RFC 2136 §3.4.1 prescan spells by hand, so it was wired in rather than deleted; `TransferError::Refused` was unreachable because the site that should build it builds `Malformed`, which left **#95**. **79b**: §17 re-measured, five fixed and two live. **79c**: closed as #89, which was it filed twice. **79d**: `set_edns` is `pub` and three answer paths use it without `mirror`, so the guarantor is `finish`'s guard, now cited and asserted. **79e**: three of six `NotFound` returns establish the wildcard invariant, not four, and the guarantor is `rdnsd`'s `resolve_in_zone` ordering — confirmed with the zone the row asked for. **79f**: 40 of `Cli`'s 46 `#[arg]` fields conflict with `--config`, so six are exempt and not three; the certificate check stays in `main` over the merged view, with the reason written in |
| **80** | two bools where the enum was already imported | **filed 2026-09-19, closed 2026-09-20**. `validate_rrset` returned `(is_valid, is_signed)`, documented in prose and nowhere in the type, with seven bare tuple literals in the file. The refuting check — a caller needing `is_signed` without already holding the `ZoneKeys` that answers it — came back empty: both production sites are in `verify_zones`, and the first calls `keys.is_signed()` one line above. `Verdict::{Unchecked, Valid, Invalid(String)}` now, and the `Invalid` carries what the pair could not: `verify_zones` said "does not verify against the zone's own keys" for an expiry, a missing signature and an unreadable algorithm alike. `validate_response` and `is_zone_signed` deleted with it, both dead and both #79a's shape in the same module; five doc comments naming the first were reworded rather than left to rot (#89). Allocation counts 33 either side; one test caught agreeing with the code for the wrong reason, which is **#94** |
| **92** | twelve wall-clock reads outside any request path | **filed and closed 2026-09-20**, and it closed with **no code change**, which was one of the two outcomes it was filed with. The deciding measurement — does any of the twelve decide a test's outcome — came back **none**: every one already takes its instant as a parameter one level down (`resign_interval_at`, `policy_for`, `apply_keeping`, `has_expired`, `expire_if_out_of_contact`), and threading a `Clock` through `Reloading`, the NOTIFY task, the replication timer and `Control` would add four constructor parameters to duplicate a seam already in use. **The closest candidate declines for a different reason and that is the keeper**: the NOTIFY client's `tsig::now()` carries #87's own argument — RFC 8945 §5.2.3's fudge makes skew visible on the wire — but `send_notify` retries over minutes, so each attempt must sign with a *current* timestamp and a seam there has to be a `Clock`, not an instant. #87's remedy does not generalize to its own other half. Written on `Clock` rather than left to be re-derived. Re-counted on closing: still 12, and the table's *files* had moved — #83 took the two NOTIFY reads out of `main.rs` the same day |
| **90** | no test spawned either binary | **filed and closed 2026-09-20**. **The refuting check the row asked for went first and came back the other way**: lifting the startup sequence out of `main` is possible and is not cheaper — `main` holds **28** top-level bindings before the dry-run exit and about twenty are live after it, so the lifted function hands back a struct built in one place and destructured in another, which is #83's reload cluster measured and declined a day earlier. One of the row's three items was **already covered** and the row had not checked: #63i's clap-introspection test has held the flag-conflict set since 2026-09-15. 15 tests landed, and they found **two defects on their first run**. A `--zone-file` that will not parse reported `line 2: ...` and **no file name**, where both sibling branches of `load_zones` name theirs — §7's second copy, and the one the smallest deployment hits. And `rdnsd --check-config` demanded a config file it does not need: `requires = "config"` was inert where it mattered (`--zone-file` conflicts with `--config`, so clap never enforced it) and misleading where it fired. That stopped being a judgement call when `rdnsr` was read — its `check_config` carries the argument against the attribute in a comment and has never had it, so one binary held the reasoning and the other held the attribute |
| **83** | `rdnsd/src/main.rs` had grown two seams | **filed 2026-09-19, closed 2026-09-20**, one taken and one declined. The method was #38d's and **the criterion had to be read first**: it counts `pub(crate)` annotations, and `main.rs` is the crate root, where §17 already records that private is not private. The NOTIFY cluster is 3 annotations against 2 sealed — a revert on the letter — while what changed is **2 items unreachable from the rest of the crate and 0 newly reachable**. Taken on the second reading. `main.rs`'s code half **1597 → 1434**, 8 imports off its non-test surface, 4 of 5 tests moved with the code. The row's "one reach-back, and it is removable" was right about the one and wrong that removing it leaves none: `&Cli` went and `absolute_name` appeared, net zero. The fifth test could not move — it needs seven `main.rs` fixtures, because it is a replication test wearing a NOTIFY test's name. **The reload cluster is declined 18 against 1**: 5 items plus 13 struct fields, since `serve` builds `Reloading` and `ReloadContext` as literals — `Cli`'s shape at a third of the size, which the row had ruled out for `Cli` without noticing the two structs beside it |
| **96** | a master that refuses the SOA probe was treated as unreachable | **filed and closed 2026-09-20**, out of #95's survey. `fetch_soa` mapped every non-NOERROR rcode to `TransferError::malformed` and `refresh_zone` propagated it with `?` before ever asking for the transfer, so a master that refuses queries and allows transfers — separate ACLs in BIND, Knot and NSD, and an ordinary hardening posture — took the zone to EXPIRE. BIND branches on exactly this rcode, with the reason in a comment: "Perhaps AXFR/IXFR is allowed even if SOA queries aren't". **#57 opened the window** by adding the probe. The variant is `Rcode(ResponseCode)` and not the `Refused` #79a deleted: the caller branches on *which* code, so it has to carry the value it caught (§2). Both rcode sites build it, and neither says "malformed" about a well-formed refusal. Two decisions settled by the survey rather than by taste: a refusal to the *transfer* still fails, and the refusal is **not** remembered per master, because BIND does not remember it either — `SOABEFOREAXFR` is cleared every `xfrdone` and NSD's per-master memory is for a bad IXFR. The measurement the row named was not needed and the row says why: it would have priced the remembering, which the field declined first |
| **95** | nothing branched on a `TransferError` variant | **filed and closed 2026-09-20**, and what it was really about was a sentence in `CLAUDE.md` §3. Measured: 38 constructions of `TransferError::` outside the enum, **not one match**. The survey then said neither of the two answers the row offered was the field's. Nobody gives up on a malformed transfer — BIND, Knot and NSD all retry, and Knot's `event_refresh` has a single `ret != KNOT_EOK` arm where the code reaches nothing but `knot_strerror` — so §3's example was invented and is struck in place. But "they all just wait out RETRY" was wrong too: BIND sets NOIXFR and retries the *same* primary on BADIXFR, NSD counts bad transfers per master and disables IXFR at three. Both branches are "remember something about this master", never "give up", and neither is between REFUSED and malformed. The branch that *is* missing is **#96** |
| **93** | an answer's owner names carried this resolver's 0x20 scramble | **filed and closed 2026-09-20**, and the measurement refuted the row. The scramble does not reach the client: the question is serialized first in the client's own case and `NameCompressor::lookup` folds ASCII, so an owner name equal to the QNAME goes out as `c0 0c`, two bytes of pointer at the question. A name the client did not send costs **four** bytes of upstream case and then points at the question for its tail — and those labels belong to the zone that published them, which is what the row itself said must not be rewritten. The row's own measurement had read `upstream.answers`, the cache, not the datagram. §4's survey agrees and corrects the row twice: **BIND ships no 0x20 at all**, and **Unbound**, which does, also does not normalize — `dname_lab_cmp` folds with `tolower` and the qname is first into its compression tree. The one implementation that would relay is BIND *authoritative*, which sets `DNS_COMPRESS_CASE` for every client outside `no-case-compress`. Pinned in `rdns/tests/case_on_the_wire.rs`, asserting the pointer rather than the rendered name |
| **94** | nothing enforced a DNSKEY's protocol field | **filed and closed 2026-09-20**, out of #80's tests. RFC 4034 §2.1.2 makes a DNSKEY with protocol ≠ 3 "invalid during signature verification"; `Dnskey::from_record` copied the octet and only `key_tag` read it afterwards, so `rdnsr` called Secure what a conforming validator calls Bogus. Both shapes built (§19) and **the measurement declined the one the row leaned towards**: rejecting in `from_record` fixes nothing, because `verify_rrset` takes `&[Dnskey]` and every field of `Dnskey` is `pub` — shape A passed the whole suite and left the new test failing, which is §17's "a `pub` field beside a checking constructor" arriving as a measurement. What landed is the predicate: `is_zone_key` wants the flag **and** protocol 3, so its three callers — the candidate-key filter, DS matching, RFC 5011 anchor candidacy — inherit it. §4's survey agrees and settled the one open choice: BIND's `dns_dnssec_iszonekey()` folds the two tests the same way, Unbound checks it in `dnskey_verify_rrset_sig` and Knot in `dnskey_rdata_to_crypto_key`; BIND alone also accepts RFC 2535's protocol 255, which is not copied. The test passed against the unfixed tree on its first draft, for a reason §1 predicts — the key tag is inside the RRSIG RDATA `signed_data` hashes, so repointing the tag after signing breaks the crypto instead of testing the field |
| **97** | `cargo deny check` by hand checked less than the job that runs it | **filed and closed 2026-09-21**. `licences and advisories` had been red on all three pushes since 2026-09-12, on `bans` alone: two `rustc-hash`, `dhat`'s 1.1.0 against `quinn`'s 2.1.3, in with `8f1be6e` (#42b). **The duplicate is the smaller half.** #91 closed five days earlier on a local `cargo deny check`, and the job was red on the next push with the duplicate already in the lockfile — because the action passes `--all-features` and the command by hand does not, so `dhat` (behind `rdnsd`'s off-by-default `dhat-heap`) is in the job's graph and not in the operator's. §1 from the other direction, and #91's verification is struck in place. Fixed in three places: a `skip` naming what collapses it (a default `rdnsd` has one copy, `dhat` 0.3.3 is the latest, so the pin is not ours), `--all-features` spelled out in `ci.yml` although it is the default, and the recipe changed to match. Plain `cargo deny check` now warns "unnecessary skip configuration", which is the two invocations disagreeing in the direction that cannot go wrong quietly. **Two licence claims fell out of the same mistake** and are corrected with it: `deny.toml` called `BSD-2-Clause` reachable for `zerocopy`, which arrives under `criterion` and is not in this graph at all, and the README enumerated six licences where `cargo deny list` reports eight. Both described the lockfile's 214 packages when the tool checks **138** — the 76 missing are `criterion`'s and `rcgen`'s dev trees — and the comment's header said so, naming `cargo metadata` as its source |
| **98** | the agent-skill config pointed at a `CONTEXT.md` that was not there | **filed and closed 2026-09-21**, out of the skills' own setup rather than a review. `docs/agents/domain.md` told them to read `CONTEXT.md` and `docs/adr/` before exploring; neither exists. The row named **no remedy**, because none had been checked (§18), and the measurement said which gap was real: the RFC vocabulary is cited in place, and the names this project coined — `ServeContext`, `Reloading`, the denial cache, **75** occurrences across **20** `.rs` files and 17 in `TODO.md` — are defined in doc comments, mentioned twice in `docs/spec/` without a definition, and nowhere else; `docs/spec/README.md`'s Conventions is the only glossary in the tree and it is two lines. Of the three shapes, the one taken was **deleting the pointer**: a root `CONTEXT.md` collides with §11's "no new design documents unless asked for by name", and a terms section grown out of those two lines is §7's second copy. The file now names where a definition lives and records the absence as a decision. **Reversed 2026-09-29 by #148**, the owner's decision |
| **99** | both daemons' dry run was a `return` at a line number, not the rule §15 states | **filed and closed 2026-09-21**, out of an architecture review rather than a defect report. `rdnsd --check-config --dnstap garbage-not-a-scheme` printed "configuration is valid" and exited 0 where the real start exits 1 — the parse sat in `serve`'s **argument list**, which is evaluated below the dry-run exit. `rdnsr`'s half is worse and was reproduced too: a TSIG secret that is not base64 passes the dry run, and `TsigKey::parse` (`:944`) runs after both `bind`s (`:766`, `:767`) and a `tokio::spawn` (`:931`), so the process takes the ports and then dies. Counted before anything was edited: **four** fallible sites below `rdnsd`'s exit, of which `--metrics-listen` in `rdnsr` is *not* one — it is a real `TcpListener::bind` and was checked before it was counted. **Both shapes were built and the type lost**: hoisting is +9 −4, a `Checked` type holding every fallible flag value is +31 −12 and still leaves **23 `cli.*` reads** below the line across 20 fields, with the enforcing version costing a 49-field mirror of `Cli` or the lift #90 declined. **The rule itself was wrong**, which is the part worth keeping: "everything that does not bind a socket" invited moving the exit down to the first spawn, and one function past `rdnsd`'s exit `discard_orphan_journals` calls `Journal::forget` — `std::fs::remove_file`. That dry run would have deleted journals. §15 now says where the exit goes instead, with the journal fact beside it, and the old sentence struck in place. One regression test per daemon, each run against the unfixed tree first |
| **100** | a dynamic UPDATE's own signatures were the only ones no run verified | **filed and closed 2026-09-21**, and the row undercounted itself. `verify_zones` had two production callers, load and reload, and an UPDATE is the third way a zone reaches the map — but the wider hole is that `ProvenSigning` skips a zone already proved for its key roles, so the *incremental* signer's output had never been checked on any path: startup proves a full sign and every incremental run after it is skipped. Fixed as the row proposed, in the type: `sign_zone_incrementally` returns `Resigned { zone, fresh }`, `sign_one_incrementally` a `FreshlySigned` whose only exit is `verify`, so a zone cannot reach the map unchecked (§17). **The set the row did not name is the one that earns the pass**: checking only what the signer says it signed agrees with a carry-forward that wrongly kept a signature over data that moved, so `verify` also takes every signed RRset at a name the update named (§19). Both sets are O(the change). `SigningRun` carries the same list for the reload path, and `Checked::resigned` counts it, so #53's saving is measurably untouched. Four tests, each watched failing; the first non-`#[ignore]`d test of the signed UPDATE path came with it |
| **103** | `server_table!` shared the field declarations and not the projection onto `Cli` | **filed and closed 2026-09-21**. The macro removed the copy that is cheap to keep right — the declarations and the defaults, where a missing default is a struct literal missing a field — and left the one where a mistake is silent: 36 hand-written assignments in `rdnsd` and 23 in `rdnsr`, where a declared key with none parsed, passed `deny_unknown_fields` and did nothing. **Probed both ways, and the row was too broad**: `dead_code` warns about a field nothing reads, so the quiet case needs a second reader — and `check` is one for 10 of `rdnsd`'s keys and 9 of `rdnsr`'s, so "validate the new key, forget to project it" built with no warning at all. Fixed by structuring the macro's own-field capture and generating `apply_to` from it, `https-path`'s keep-the-default exception included; 59 statements became none, and a key with no `Cli` field is now `error[E0609]` pointing at the declaration. `every_server_key_reaches_its_flag` is the full-fixture test the row said was missing, one per daemon, asserting the value so a cross-wired key fails too — green against the old projection, and naming `max-tcp-request` with one line deleted from it while the old tripwire stayed green |
| **104** | four digest caches over one `FileDigest`, with the reasoning built on it copied | **filed and closed 2026-09-21**, and asking the question found two defects rather than a duplication. `rdnsd`'s UPDATE path parsed with `parse_zone_file`, which has no base directory and resolves `$INCLUDE` against the *process's* working directory where the loader resolves it against the zone file's — a SERVFAIL for a file the loader reads. Under it, and reachable only once that was fixed: the digest was `FileDigest::of` over bytes read off disk, so a no-op UPDATE remembered the digest of an `$INCLUDE`-bearing parent and the next UPDATE matched it while the *included* file had moved. Reproduced: `www` served `192.0.2.9` after the include had been rewritten to `198.51.100.77`, and the file was written back flattened with neither the directive nor the new address in it (`CLAUDE.md` §4). **Both are one check at the boundary**: `of_self_contained`, with `None` a REFUSED — a file built out of includes is not a writable source, because it cannot be written back as one. **The count is declined on a measurement**: `LoadedFiles` and `Keepable` are one cache and a policy layer, `UpdateHandling::applying` lives under the §3.7 mutex on purpose, and `PolicyStore.offered` is a `Vec` of zones rather than a digest map — two maps and a list, two crates, three lock kinds. What they share is `FileDigest`, which was already shared, and the `stat` argument, which is now on it once instead of written out at two call sites. `PolicyStore::offer`'s "the caller writes `text` to `path` first" became `zone_writer::Written`, which only the write makes (§17) |
| **105** | `https::answer` charged the rate limiter whatever the caller asked for | **filed and closed 2026-09-21**, and the row's own framing was the first correction: the review said `RateLimit::PerConnection` had no production caller, and `rdnsr` passes it to all four of its listeners. What survived is worse — `https::serve` charged `allow_source` at accept and `answer` charged again for every request, so the first request of every DoH connection paid twice and `--query-rate` meant one thing over DoT and another over DoH. Reproduced: a burst of one, and the first request of the first connection came back `429`. **The open design question has an answer that leaves #30e alone**: #30e is about the two *daemons* disagreeing, so the parameter and its call sites stay; what became one is the four *adapters*' reading of it. `RateLimit::admits_connection` and `admits_message` are a pair, so a caller that asks both charges once whatever the policy is — seven places in `rdns-transport` spelled the predicate, four accept blocks and two per-message `if`s and one call that consulted nothing, and two do now. Where a refusal lands is now stated: before the TLS handshake under `PerConnection`, so a dropped connection rather than a 429 |
| **106** | a DoH transfer was built in full and discarded | **filed and closed 2026-09-21**, and measuring it first found worse than the row claimed: the three-record fixture **transferred** over DoH, because one envelope is a whole AXFR (RFC 5936 §2.2) and `https::answer` takes the first frame as its body. So DoH carried a transfer when the zone was small and serialized the whole zone into a discarded channel when it was not — succeeding by zone size, which passes every fixture and fails the deployment. `Arrival::carries_a_sequence` is the fourth question that type answers, beside `peer_certificate` and `privacy`, because every adapter that builds an `Arrival` has already decided it. The refusal goes in `answer_transfer` beside `--transfer-tls-only` rather than at the dispatch that chose to stream: that is the function that logs an attempt, signs a refusal when the request was signed (§16), and already runs before the zone is looked up. First of the three, because no configuration or credential can change it. **It narrows something that worked** and nothing defines that something — RFC 8484 gives no framing for a sequence and RFC 9103 §7.1 puts DoH outside zone transfer. `https`'s drain stays as a backstop, since `Handler` permits a sequence for `tcp` and `quic` |
| **101** | the TSIG-rejection branch returned past the dnstap tail | **filed and closed 2026-09-21**, out of the same review as #99 and the same shape: a rule stated in a comment and held by nothing. #75 gave `Server::answer` one tail so nothing could `return` past `record_dnstap`, and the comment at `dispatch.rs:311` said "three ways to answer and one tail". There were four — the `TsigCheck::Rejected` arm sends a NOTAUTH at `:289` and returns at `:292`, sixty lines above the tail — so a capture under a key-guessing probe, which is the one time an operator wants it, held nothing. The test that locked #75 in asserted 3, so the fourth door was invisible from the comment and from the suite at once. Fixed by making the check an expression: both arms produce `Option<Cow<[u8]>>`, the refusal returns what it sent, and the rest moves to `answer_admitted` behind an `Admitted` struct — six values that travel together, because the method wants nine parameters and clippy stops at seven (§14). **The cheapest of the three shapes was the one declined**: a `Drop` guard on the tail is a few lines and makes the record impossible to skip while leaving it easy to hand nothing, which reports "no reply" for a request that got one — the same symptom, quieter. The `let ... else { return; }` in the refusal became a `match` as a consequence, since "no reply fits" is now a value rather than a divergence. Test count 3 → 4, run against the unfixed tree first (`left: 3, right: 4`) |
| **102** | `Answered::refresh` survived thirteen exits by inspection | **filed and closed 2026-09-21**. `refresh` was a `mut` local declared 226 lines above the cache hit that set it and 200 below the tail that read it, with thirteen `.into()` exits in between and a `From<Option<Vec<u8>>>` that fills `refresh: None` for free — #78a is the time one of those exits silently turned prefetching off for any name an `rpz-ip` rule matched. Fixed by deriving it from the lookup: `hit.as_ref().filter(|hit| hit.refresh).map(|_| query.clone())`, immutable, one line below the `lookup` it comes from. The invariant stops being "read all thirteen exits" and becomes one implication — `refresh` is `Some` only when `hit` is, and both exits that could drop it are in the arm that runs when the cache *missed*. **Both halves of the row's own guess were wrong**: the `From` impl was not the defect and stays, because once the local is gone `.into()` is correct by construction at every one of the thirteen sites, and deleting it would have made them noisier and fixed nothing. No behaviour changed, so there is no new test — a test here would agree with the code (§1); #78a's *A rewritten answer still asks for its prefetch* is still the guard. The old comment's argument is struck in place rather than rewritten, because it is the lesson: "falling through leaves one exit, so there is nothing to remember" held for the exit that had just been removed and said nothing about the next one |
| **81** | what #63h's macro did not reach, and one more copy | **filed 2026-09-19, closed 2026-09-20**, two rows. **81a** measured and mostly declined: of the 27 commits touching `rdnsd/src/config.rs`, 8 touch its TSIG lines and 1 of those also touches `rdnsr`'s — and that one *created* the copy — so the two tables do not co-move and the shared struct is declined; three fields of five are shared, not five, because a resolver authorizes nothing. What was taken is the list and the default under it: `TsigAlgorithm::ALL`, `::ACCEPTED_NAMES`, `::DEFAULT`, with `TsigKey::parse` coming out better than it went in. **81b** merged the two FNV-1a loops into `rdns_core::folded_hash`, and the check was the row's own instruction taken through the observable rather than by comparing the copies: six `expiry_for` offsets measured before the merge, unchanged after it, so no signature's expiry moved |
| **82** | two modules in the wrong place, and a `pub` with no ratchet | **filed 2026-09-19, closed 2026-09-20**, two rows. **82b** took the ratchet: 43 sites, 38 of them `#[cfg(test)]` fixtures that always meant `pub(crate)`, and `#![warn(unreachable_pub)]` is in all nine crate roots with what it does *not* answer written on the lint. **82a** moved `readiness` to `rdns-transport`, whose metrics server serves `/readyz`; the estimate held except that a move is two `mod` lines, not one. Both halves of the *larger* version stay declined on measurements taken in place: an `rdns-ops` crate takes no package off any binary (`cargo tree -p rdnsd` is 150 either way) and the transport link is ~450 ms of a ~3.3 s rebuild, which is a ceiling and not a saving |
| **84** | `to_prometheus_format` was 337 lines of one idiom | **filed 2026-09-19, closed 2026-09-20**, and the row's own remedy was wrong by an order of magnitude. Both shapes built (§19): helper calls 278 lines, a table 276, against 337 — because stock rustfmt breaks *every* element of an argument list when one exceeds 100 columns, and §12 forbids a `rustfmt.toml`, so the length was never available to be fixed. The table shipped on what it makes unrepresentable instead: name, help and field on one row, so a counter rendered nowhere is a missing row rather than a missing block among thirty. The `diff` the row asked for came back **byte-identical except the `dns_catalog_members` HELP line**, its 22 stray spaces, exactly as predicted. One it did not ask for: a scrape was **65 allocations and is 16** for the same 4 775 bytes, pinned. Both sub-findings fixed — `the_scrape_is_well_formed` asserts one HELP and one TYPE per family, no undeclared sample and no padded help text, and fails against the padded line put back; the two lock guards read *through* a poisoned lock now, matching the decision every writer in the file had already made, because dropping the series made every zone look withdrawn at once |
| **78** | `rdnsr`'s query path lost work at three of its exits | **filed 2026-09-19, closed 2026-09-20**, three rows, and the first was verified here while b and c were the review's reading — both held. **78a**: an `rpz-ip` rule over a cache hit dropped the prefetch the answer cache had just asked for, because `impl From<Option<Vec<u8>>> for Answered` fills `refresh: None`. Three shapes built (§19) and the one that shipped is in neither the row nor the review: delete the early `return`, since the hazard is §7's jump over a shared epilogue. **78b**: `Resolver::forward` returned the upstream's AA bit and echoed question verbatim where `recurse` normalized both, so an `rdnsr` in front of an `rdnsr` running 0x20 would have rejected its own answer (RFC 5452 §9.1) — left **#93**. **78c**: QDCOUNT = 0 was dropped by `rdnsr` and answered NOERROR *with AA set* by `rdnsd`. RFC 9619 §4 settles only QDCOUNT > 1; its QDCOUNT = 0 sentence binds firewalls, not responders. RFC 7873 §5.4 says what the query is for and that a server without cookies "will normally send FORMERR", and the peers agree: BIND 9.20.27, Knot 3.6.0, NSD 4.12.0 and Unbound 1.23.1 all answer it, all FORMERR with no OPT, and none drops it — which is the measurement that could have refuted the finding |
| **107** | eleven wall-clock reads inside a request path, in the crate #92 did not count | **filed 2026-09-21, closed 2026-09-22**. The eleven are exact and the crate held **fifteen**: the other four are two constructors, a background timer — #92's own category — and `DnssecValidator::validate_rrset`, which is not. `NsecCache`, `DelegationCache` and `KeyCache` take a `Clock` now, `Resolver` holds one and `validate` reads it; the two resolver caches *require* it, since both are `pub(super)` with one production caller, so a cache built without one does not compile (§17). Two tests that could not be written now are: a proof live at +0, +1 800 and +3 599 and gone at +3 601, and a delegation inserted through the public path instead of forged through the mutex — the forgery existed because `insert` clamps `expires_at` to `now + ttl`. **`validate_rrset` declines and the measurement is why**: it is request-reachable, though not by the route triage first named (`dispatch.rs:2433` is `#[cfg(test)]`; the real one is the UPDATE path's pre-install `FreshlySigned::verify`), and the instant it wants is choosable through `SigningPolicy` — #92's own criterion. `clock.rs`'s sentence is struck and corrected, which is what the row was filed for |
| **108** | `min(SOA MINIMUM, the SOA's own TTL)` written five times | **filed 2026-09-21, closed 2026-09-24**. `Ttl::negative_answer(soa_ttl, minimum)` in `rdns-core::codes`, and the five call it. **The open shape question picked the signature**: four sites hold a record — two `ZoneRecordRef`, two `ResourceRecord`, all four spelling the inputs `ttl` and `rdata.soa_minimum()` — but `zone_signer` holds the `(Ttl, u32)` that `carry_over_records` split out of the SOA 200 lines earlier, so a record-shaped helper would have missed the one site the defect was found in. A sixth candidate is not one: `rdnsr/src/answer.rs:1087` hands the client both numbers and says so. **The larger half is the one the row did not name.** Behaviour is unchanged, so the only thing that can be watched failing is the drift — and reverting `negative_answer` to each one-term spelling found that **not one of the five sites had a test for both**: `rdnsd/answer` had neither, `zone_signer` had only #111c's split guard (which fires because the harness re-spells the rule), `dnssec_answer` had the SOA-TTL direction only and the two caches the mirror of it. Every gap is a fixture: three are `$TTL 3600` over `minimum 300`, #73's masking direction a third time, and the answer path cannot show MINIMUM winning over a zone *this* server signed, because the signer capped the chain first. Five tests added, each watched failing; both drifts now fail at all five sites. 1 304 → 1 309 passed on Windows, 1 330 on Linux, 0 failed |
| **109** | `struct Server` in the crate root, its implementation in `dispatch` | **filed 2026-09-21, closed 2026-09-24**. `Server` and `UpdateHandling` moved to `dispatch.rs` with all 15 fields private; the root builds one with `Server::new` and six `with_*`, and reads `ctx()`, `tsig_keys()`, `zone_context()`. 13 `pub(crate)` items against 15 fields hidden, #83's predicted loss; paid for by nothing outside `dispatch` reading an ACL, a keyring or the UPDATE lock, and by six test literals losing their refusing defaults. The row counted 2 literals and there were 7. The test half is #116. See `docs/closed/109.md` |
| **110** | one-victim eviction scans left after `Halving` | **filed 2026-09-21, closed 2026-09-24**. Measured before changing, as the row asked: 17-21 µs per insert at the default 10 000, 2.7-8.6 ms at a million, linear in `--delegation-cache-size`, against 0.1 µs with room — #33a's cost again. Five sites, not four: `RttStore` scanned for the slowest server and ranks by speed, so the grep missed it. All three resolver maps halve through `crate::eviction`; `RttStore` slowest first. The two in `nsec_cache` stay, both with the reason. Guard watched failing at 357-418x. See `docs/closed/110.md` |
| **112** | price the reload cluster's constructors | **filed 2026-09-21, closed 2026-09-24**, constructors declined. The row's reason for them was wrong twice: the test module already built three `Reloading` literals, and `tokio::time::pause` needs `test-util`, which nothing enabled. Left with #83's 5-against-1 visibility loss and no test to pay for it. The test gap was real: three tests for `spawn_zone_maintenance` — control reloads answered and the stop drains, no timer without keys, a timer with them under paused time — each watched failing against its own mutation. The keepalive clone is unobservable (`select!` disables an unmatched arm); recorded, not changed. See `docs/closed/112.md` |
| **113** | #103's projection sweep stopped at `[server]` | **filed 2026-09-21, closed 2026-09-24**. Measured first: a `[resolver]` key nothing reads warns, an `[rpz]` key only `check` reads compiles clean — both as the row said. The shape is eight sections across both daemons, not two. Each projection now destructures its table with no `..`, the top-level `Config` too, so a key added and not handled is `E0027`; the probe that compiled clean now fails naming the field. No macro: none of the eight is shared between daemons. See `docs/closed/113.md` |
| **114** | the prefetch ran inside `Handler::handle`, before DoH's answer | **filed 2026-09-21, closed 2026-09-25**. The row counted two hand-written discharges; the TCP one is shared by four transports, and on DoH and DoQ it was a live defect. DoH responds once the handler task is joined and DoQ sends FIN once the sink closes, so a prefetch-due name's reply waited for the upstream (0.9 ms reply, 1.51 s to close, provoked). `rdnsr/src/prefetch.rs` puts refreshes on a bounded queue and pool (`--prefetch-workers` 16, `--prefetch-queue` 256, drops counted in `dns_prefetches_dropped_total`, no `Busy`); `Answered` is gone and the contract is on `Handler::handle`. Three remedies that keep the work in the handler are declined in the section. See `docs/closed/114.md` |
| **116** | `rdnsd`'s answering tests were in the crate root | **filed 2026-09-24, closed 2026-09-25**. The harness was the only thing holding them: a root-private item is visible to every descendant (§17), so moving the tests widened nothing. 58 of 90 moved by subject — 23 to `dispatch`, 15 to `replication` (which had none), 13 to `answer`, 7 to `zones` — and 32 stay because they test root items, the reload cluster among them (#83). 17 fixtures to `testutil`; `zone_text(serial)` became `zone_at_serial` to stop it clashing with `dispatch`'s benchmark helper. Three docs older than the change were wrong, `Server::serve_connection` among them. Same 210 test names, same totals. See `docs/closed/116.md` |
| **117** | `refresh` claimed the query path's storing; prefetch and DNS64 never fed the denial cache | **filed and closed 2026-09-25**. The reason given for storing less was about the reply, not the cache. `Caches::store` holds the four rules and both writers call it. Regression test: a refreshed Secure NXDOMAIN answers the rest of its NSEC gap with no second upstream query, asked twice with the old storing restored. `testutil::SignedZone` is the first Secure resolution `rdnsr`'s tests can reach. Declined: DNS64 consulting the denial cache, since CD would have to be passed in to agree. See `docs/closed/117.md` |
| **118** | `answer_update` checked permission before the zone, and its doc claimed the RFC's order | **filed and closed 2026-09-25**. BIND, Knot and PowerDNS read: all check permission before §3.2, two of three check the zone before permission. Now zone → permission → prerequisites, so an unsigned or wrongly scoped UPDATE for a zone not served is NOTAUTH. The conformance row lists the two deviations, one of them the replicated-zone REFUSED where §3.1.1 forwards. See `docs/closed/118.md` |
| **119** | two UPDATE refusals no test reached, and an unreadable zone directory answered REFUSED | **filed and closed 2026-09-25**. SERVFAIL now, as a failed read of the zone file already was: RFC 2136 §4.6 sends the client to the next server on SERVFAIL and ends the update on REFUSED. `file_for` propagates `read_dir` and entry errors as the loader does. Four tests; the task-failure SERVFAIL stays untested, reachable only by a panic. See `docs/closed/119.md` |
| **68** | a socket test failed once under a parallel suite | **filed 2026-09-15, closed 2026-09-25.** The test it named never failed again; two others in `rdnsd` did, 8 in 200 workspace runs. 68a was a defect: dnstap's pump dropped its queue on stop, frames already counted as sent, so a capture lost its last requests (50 of 50 provoked runs). Now drained before STOP. 68b was the test's: an unanswered NOTIFY is resent after 2 s. 0 in 200 runs after. The same 200 runs filed **#120**. See `docs/closed/068.md` |
| **58** | serve-stale answered a dead upstream and not a slow one | **filed 2026-09-13, closed 2026-09-25.** RFC 8767 §5's 1.8 s client response timer declined on a survey of BIND, Unbound, Knot and PowerDNS — BIND removed it after two CVEs — and BIND's zero form taken as `--serve-stale-first`, refreshing through #114's prefetch pool. A deviation from §4, filed as **D-8** in #21. The timers were §5 and nine places said §4. Two things the grooming did not see: a stale refresh has to be a *period* (§5's 30 s failure recheck), or one failure leaves a name stale and untried for the whole window; and the pool's presence had been the prefetch switch. See `docs/closed/058.md` |
| **120** | three timing flakes found verifying #68 | **filed and closed 2026-09-25.** 120a: the TCP stop tests slept 20 ms and hoped the server had read the query; the handler now says so. 120b: all twelve ratio tests opened — four already took a minimum, one is not a suite test, seven took one sample and now take the best of five through `rdns::testutil::fastest`. After: 0 failures of any of them in 150 Windows and 50 Linux runs, against 4 before. The same runs filed **#121**, a real signing defect, and **#122**. See `docs/closed/120.md` |
| **122** | ratio tests took five of one side, then five of the other | **filed 2026-09-25, closed 2026-09-26.** Measured first: `zone.rs`'s test under load failed 5 in 900 sampling one side then the other, 0 in 900 taking turns, with the same median. `rdns::testutil::fastest_of_each` takes turns, and all eleven suite ratio tests use it; `fastest` is gone. The verification filed **#123** and **#124**. See `docs/closed/122.md` |
| **121** | incremental signing took a key tag for a key | **filed 2026-09-25, closed 2026-09-26.** A new ZSK whose tag matched the old one's read as "keys unchanged", so the old signature was carried alone and the new DNSKEY signed nothing; a swapped-in twin carried a signature from a withdrawn key. Condition 3 now holds only when each signer's tag names exactly its own DNSKEY in the previous run's RRset, checked once per run. A stored colliding Ed25519 pair tests both cases, each watched failing before. Filed **#125**, a collision in `--generate-keys` overwriting a private key file. See `docs/closed/121.md` |
| **123** | two resolver tests timed out under load | **filed and closed 2026-09-26.** The row said they failed before their timeout; each server gets `timeout_ms / 2`, and every failure was that 2 s expiring. The fake never received the query: CPU load alone reproduced it, 7 in 20 runs, with no other network traffic. It polled its stop flag with a 50 ms `SO_RCVTIMEO`, which Windows documents as leaving the socket "in an indeterminate state"; a datagram arriving as it fired was lost. Now a task on the test runtime, aborted on drop. Under 64 spinners, old 25 of 25 runs failing, new 0 of 25 — `zone.rs`'s ratio test included, which the old fakes were disturbing. See `docs/closed/123.md` |
| **124** | `compression.rs`'s ratio test near its bound in debug | **filed and closed 2026-09-26.** The bound was right: the unindexed scan reads 13-15× in debug, the ~2 was release. The samples were not: 500 writes against 16 000, so under load only the long side was preempted — loaded Linux read 6.16× median, 195 of 200 over 5, and more samples did not help. Both sides now write 800 names a sample, best of fifteen: max 3.26× loaded, and the real test failed 0 of 100 there against 83 before. See `docs/closed/124.md` |
| **125** | `--generate-keys` replaced a key file whose tag it collided with | **filed and closed 2026-09-26.** Checked against BIND first: `dnssec-keygen` generates again while a new key's tag, or its tag with REVOKE set, equals either tag of a key of that name and algorithm in the directory (`key_collision`, `dnssectool.c`). `SigningKey::distinct_from` does the same against the directory and the run's other key, bounded at 100 attempts; `write_to_dir` publishes by hard link and refuses an existing file. Tested over #121's stored pair, a stored REVOKE-apart pair and a same-tag pair of two algorithms; the overwrite test watched failing against the old rename, and `rdnsd`'s wiring test against dropping either list. See `docs/closed/125.md` |
| **126** | `--generate-keys` left a KSK with no DS when the ZSK's write failed | **filed and closed 2026-09-27.** Found reviewing #125. `write_key_pair` now removes whatever of the pair reached the directory on any write error, by `SigningKey::remove_from_dir`, which compares content rather than trusting the name: the name is the tag, and a file under it holding anything else is a colliding key. A key that cannot be removed is named in the error. |
| **127** | a cached wildcard synthesis counted neither a hit nor a miss | **filed and closed 2026-09-27.** Found by the deepening sweep that filed #128-#130. `rdnsr`'s RFC 8198 §5.3 arm returned before `cache_hits`, where the other three arms answered from something held count one. One line; the test failed on 0 hits against the old arm. |
| **128** | RFC 1035 §4.3.5's refresh cycle was written twice and neither copy was tested | **filed 2026-09-27, closed 2026-09-28.** Both shapes built: one cycle in `rdns::secondary` (A) against paused-time tests on each loop (B). A taken: B's tests need real loopback I/O under paused time and a 200 ms real-time quiet period, without which the REFRESH test passed the bug it was for, and they are the same six tests twice. The copies had drifted three times: #135, `rdnsr`'s missing stop guard, and the timers after an expiry. Branches `128-shape-a` and `128-shape-b` kept. See `docs/closed/128.md` |
| **129** | `Caches` sealed its write side and left the read order to its callers | **filed and closed 2026-09-27.** `Caches::lookup` holds the order; `handle_query` has one hit arm. Found doing it: `cached_or_resolve` asked `answers` before `negatives`, so DNS64 synthesized from an A a newer "no" had replaced. Regression test failed against the old order. See `docs/closed/129.md` |
| **130** | four UPDATE refusals had an EDE or rcode no test asserted | **filed 2026-09-27, closed 2026-09-28.** Filed as "decides and replies in one pass"; triage found the socketless seam existed and the evidence was not about interleaving, so no type. NOTAUTH's, the scoped key's and no-source's EDE and the `$INCLUDE` rcode and EDE are asserted at the reply; each mutated exit failed one test. See `docs/closed/130.md` |
| **131** | a zone with two masters was withdrawn when one of them was down | **filed and closed 2026-09-27.** Found grooming #128. EXPIRE and the startup/reload vouch read the sidecar per (zone, master); RFC 1034 §4.3.5, BIND and Knot count contact per zone. `StateFile::last_contact` over the masters configured now, so a line from a master no longer configured still vouches for nothing. Both regression tests failed against the per-master lookup. |
| **132** | a stale lookup served an older "yes" over a newer "no" | **filed and closed 2026-09-27.** Found grooming #129. `Caches::stale` serves the later of the two by `learned_at` (RFC 8767 §4), deciding at read time because an NXDOMAIN is keyed by name and retiring on store would scan the answer cache. Covers other types at the name. Stale NXDOMAIN kept (RFC 8914 §4.20). Both regression tests failed with the "yes" asked first. |
| **133** | the fresh path could serve an older "no" over a newer "yes" | **filed and closed 2026-09-27.** Found closing #132. `Caches::store` has an answer retire the NODATA for its question and the NXDOMAIN at its name and every ancestor (`NegativeCache::forget_refuted`), so asking `negatives` first is right by construction; one removal per label, no scan. The read side was not built. Both regression tests failed without the call. The denial cache has the same shape: #134. |
| **134** | a cached RFC 8198 gap or wildcard outranked a newer answer for the name | **filed and closed 2026-09-27.** Found closing #133; the wildcard instance found triaging #129. RFC 8198 Appendix A, Unbound, BIND and Knot Resolver ask the exact-match cache first and synthesize on a miss; `Caches::lookup` now does too. Neither store-side retiring nor `learned_at` on proofs was needed. Both regression tests failed against the old order; a cache hit went from 13 allocations to 12. See `docs/closed/134.md` |
| **135** | a restarted `rdnsr` whose master was gone never reached EXPIRE | **filed and closed 2026-09-27.** Found triaging #128. `refresh_task` started from `RefreshTimers::default()`, EXPIRE never, and held a feed file from the last run; it now starts from the timers of the zone in force. The regression test failed against the default. See `docs/closed/135.md` |
| **136** | the resolver's tests reached it only through a loopback hierarchy | **filed and closed 2026-09-28.** Both shapes built: an `Upstream` seam under `ask_any` (A) against one shared fake behind a `test-util` feature (B). A taken: it removed `ResolverConfig::server_port`, a `pub` field that existed for tests, and B kept it and added test code to `rdns`'s public surface. 46 resolver tests and 3 `rdnsr` tests answer from a table; socket behaviour stays on sockets, plus a source-filter test that did not exist. Filed **#137**. See `docs/closed/136.md` |
| **137** | nothing tested fastest-first server order end to end | **filed 2026-09-28, closed 2026-09-29.** Found closing #136. `Upstream::Answering` returns a future and `ask_any` reads `tokio::time::Instant`, so a paused test makes one server slower than another. A per-server latency table built and declined. `15d9add` |
| **138** | an NSEC3 salt over 255 octets was encoded with the wrong length | **filed and closed 2026-09-28.** Found by the idiom review. `u8::try_from` at both lengths: a 256-octet salt loaded with length 0 and reparsed as another NSEC3, and now fails the zone at its line. `9431916` |
| **139** | TSIG read a key name off the wire as lossy, unescaped text | **filed and closed 2026-09-28.** Found by the idiom review. Read with `rdns_core::Name` and carried in presentation form, so escapes survive; our own request was BADKEY for `a\.b.`. Not a bypass. `248bdc0` |
| **140** | an NSEC type bitmap folded its type names with the Unicode fold | **filed and closed 2026-09-28.** Found by the idiom review. `N\u{17f}` loaded as NS; `upper_into`'s ASCII fold now, #26b's fix one file over. `a40c305` |
| **141** | the config file refused a key reference the flags accept | **filed and closed 2026-09-28.** Found by the idiom review. `rdns::tsig::same_key_name`, `by_name`'s comparison, at all three config checks; `#partner.key` for `partner.key.` was refused by `--check-config` and accepted by the flags. `9f3524d` |
| **142** | poison recovery was spelled two ways | **filed and closed 2026-09-28.** Found by the idiom review. `unwrap_or_else(PoisonError::into_inner)` at 13 sites, two more than the row counted. `a26a938` |
| **143** | fourteen `push_str(&format!(..))` in production code | **filed and closed 2026-09-28.** Found by the idiom review. `write!` at 42 sites, 16 of them production; `clippy::format_push_string` on in every crate root. `07d2719` |
| **144** | six copies inside one module each | **filed and closed 2026-09-28.** Found by the idiom review. One helper each in `rpz`, `catalog`, `denial_wire`, `codecs`, `dnstap`; `ancestors()` in `negative_cache`. `c34236e` |
| **145** | work done twice or thrown away | **filed and closed 2026-09-28.** Found by the idiom review. 145a-d fixed; 145e became #147; 145f declined on a measured no-change. `1009089` |
| **146** | small idioms, one sweep | **filed and closed 2026-09-28.** Found by the idiom review. `Class::IN` at all 203 sites, and eight smaller rewrites. `1e6e39e` |
| **147** | a zone-file field past a name's RDATA was joined into the name | **filed and closed 2026-09-28.** Found probing 145e. `NS ns1.example.com. junk` served `ns1.example.com.\032junk.example.com.`; a name is one field now, MX two, SOA seven. `a5ea7e8` |
| **148** | domain docs moved to the mattpocock layout | **filed 2026-09-29, closed 2026-09-30.** Reverses #98 on the owner's decision. `docs/agents/domain.md` in the skills' shape; #21's deviations are `docs/adr/0001`-`0005`, the rest move when touched; `docs/spec/07`'s two D-8s split into D-8 and D-9. See `docs/closed/148.md` |
| **149** | eleven em dashes in comments were double-encoded | **filed 2026-09-30, closed 2026-10-01.** Found reading `answer.rs` for #148; all U+2014, all from #44b. The scan reads 0 over every tracked file; `CLAUDE.md` §12 carries the check. `96f26dd` |
| **150** | the authoritative answer was split across the `rdns`/`rdnsd` seam | **filed 2026-10-01, closed 2026-10-02.** `rdns::zone_answer::write`, with the proofs private to it; `rdns`'s counts, panic sweep and bench go through it. Found #160. `d19d6e5`, `66199ad` |
| **152** | the re-signing interval came back without the rule that chose it | **filed 2026-10-01, closed 2026-10-02.** `Resign { every, why }`; the startup line is its `Display` and no longer spells the fraction. `3348cad` |
| **153** | the encrypted listeners were configured, bound and spawned in both daemons | **filed 2026-10-01, closed 2026-10-02.** `Encrypted` and `EncryptedListeners` in `rdns-transport`; `rdnsr` now names its listeners on startup and in `--check-config`. `34bfceb`, `2e248e5` |
| **154** | a cache entry's expiry had no type, and seven of eight constructions did not saturate | **filed 2026-10-01, closed 2026-10-02.** `Deadline`, with the RFC 8767 stale-refresh claim on it (154a). Four of five near-`u64::MAX` tests panicked before. `659ac8f` |
| **111** | the signing cost harness was a copy of `sign_zone_inner` and had drifted | **filed 2026-09-21, closed 2026-09-22**, five sub-items. 111a fixed the two drifts named, both latent — the fixture is `$TTL 3600` over MINIMUM 3600, and one SEP plus one ZSK never empties a half. 111b fixed the one not named: no `policy.chain` branch at all, so an NSEC3 zone was unmeasurable. 111c is the guard that runs — record for record under Ed25519, whose signatures are deterministic, with all three drifts watched failing it. 111d found the ratio assertion failing 2 runs in 3 on Linux at 10 000 records and always having done: the whole was timed on its first run at a size while the parts inherited a warm allocator, 39.2 ms against 31.1. **111e is 111d's own remedy going wrong** — warming one side made the whole 33.2 s against 28.2 at a million on Windows, where Linux read 1.015 on the same code, so both sides are warmed now |
| **115** | two pieces of `rdnsd` prose that were wrong in the tree | **filed 2026-09-21, closed 2026-09-22**, and re-measuring the row before fixing it corrected the row. The duplicated RFC 8945 §5.2 comment above `tsig::check_request` came in with `955504d` (#101) and is byte-identical to the `dc9d64ab` pair under it; the shape is 1 tree-wide before and 0 after. The config module doc's 46/40 were stale — **and so was the correction**: 51 `#[arg]` over **51** fields, not 49, because `nsec3` and `nsec3_opt_out` fall outside a `[a-z_]+` scan. A row filed to fix a stale number wrote one it had not read, which is the reported defect committed a second time, so it is struck in place (§11). **Fixed by deleting the counts rather than refreshing them**: the rule already has a guarantor in `a_setting_the_file_can_write_is_refused_beside_config`, which walks `Cli::command()` and requires a flag not refused beside `--config` to have no key in the file — clap owns one half and serde the other — so the doc cites the test and carries no number that can drift (§17). No code changed and no test was added: a count assertion would be a second authority to keep in step, which is the defect. 1 302 passed on Windows, 1 323 on Linux, 0 failed |
| **155** | the stream listeners' connection ceiling and idle timeout had no flag, and reaching the ceiling was invisible | **filed 2026-10-02, closed 2026-10-03.** `--max-connections` and `--connection-idle-timeout` in both daemons, non-zero by type; the slot is taken before `accept`, with a gauge, a wait counter and one WARN per episode. Found #161: DoH never applied the idle timeout. `05d4668` |
| **157** | the query and response limiters keyed on the exact peer, so a host rotating within its /64 was never limited | **filed 2026-10-02, closed 2026-10-03.** `rdns::peer::Source` (IPv4, IPv6 /56) and `ResponseTarget` (IPv4 /24, IPv6 /56); the logger keys on `Source`; a full table is counted in the scrape. `cccd5c0` |
| **158** | on a dual-stack socket, IPv4 rules did not match IPv4 clients | **filed 2026-10-02, closed 2026-10-03.** `rdns::peer::Peer`, canonical by construction, taken by every check — five, the fifth being RPZ client-IP triggers; the UDP reply keeps the socket's address. `edfd99a` |
| **159** | `--host ::` was dual-stack on Linux and IPv6-only on Windows | **filed 2026-10-02, closed 2026-10-03.** `rdns_transport::bind` sets `IPV6_V6ONLY` 0 on every listener, DoQ included; the startup line and `--check-config` name the families. `a842f47` |
| **156** | one source could hold every connection a stream listener had | **filed 2026-10-02, closed 2026-10-03.** Narrowed in triage to RFC 7766 §10's per-source item; `--max-connections-per-source` (32, per IPv4 address or IPv6 /56) with its own exemption list, closed with no reply over it, counted and logged once a minute. `0fd0a55` |
| **151** | the chain-of-trust walk had no type, so its RFC rules lived in the async loop | **filed 2026-10-01, closed 2026-10-03.** 151a reproduced a secure answer going Bogus when a key set expired mid-resolution; 151c fixed it with trusted starts. Both shapes were built and the owner took the walker: `dnssec_chain::ChainWalk`, all nine walk rules synchronously tested, a resumed validation 122 allocations against the loop's 124. `2508d1b`, `3935df9`, `b8dcc95`, `d407877`, `4244af4` |
| **162** | a TLS handshake had no deadline on DoT or DoH, so a peer sending no ClientHello held a connection slot | **filed 2026-10-03, closed 2026-10-03.** Found triaging #161. `tls::handshake` bounds both by `--connection-idle-timeout`; an expiry is a handshake failure. `4e9d9be` |
| **161** | a DoH connection was never closed for being idle | **filed 2026-10-03, closed 2026-10-03.** Idle is no new request started; GOAWAY or the HTTP/1.1 exchange finished, dropped one `--connection-idle-timeout` later; shutdown takes the same path. `6f95f74`, `34a57a2` |
| **160** | `rdnsd`'s fold buffer was passed to nothing since #38, and a DNS-0x20 query allocated twice to fold | **filed 2026-10-02, closed 2026-10-03.** Found closing #150. Both folds onto the stack with `folded_into`; the buffer deleted. Case randomized 4.0 -> 2.0 allocations a query under dhat, same as lower case. `3759784` |
| **163** | a TCP or DoT peer that never read its replies held its connection, slot and the shutdown drain forever | **filed 2026-10-03, closed 2026-10-03.** Found grilling #161. Each reply is written under a progress deadline of `read_timeout`, and the read loop ends with the writer. `0d0d5f2` |
| **164** | a DoQ client's packets kept an idle connection open, PINGs included | **filed 2026-10-03, closed 2026-10-03.** Found triaging #163. DoQ's idle is no new stream, as on TCP and DoH; in-flight streams get one more timeout, at idle and at shutdown; a missing FIN closes with `DOQ_PROTOCOL_ERROR`, a starved reply resets with `DOQ_UNSPECIFIED_ERROR`. `9fa0fa5` |
| **165** | DoQ answered every stream error with a stream reset and `DOQ_PROTOCOL_ERROR` | **filed 2026-10-03, closed 2026-10-04.** Found grilling #164. Framing errors close the connection (RFC 9250 §4.3.3), a client reset gets `DOQ_NO_ERROR`, a refused query `DOQ_UNSPECIFIED_ERROR`, an abandoned transfer `DOQ_INTERNAL_ERROR`; bytes after a query had been answered. See `docs/closed/165.md`, `17823c4` |

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
