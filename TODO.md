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

**#58**, **#68**, **#92**, and **#21**, as of 2026-09-20.
**#93 closed** on a measurement that refuted it. **#95 and #96 closed
together**: #95's survey said §3's example of a branch was invented, and found
the branch that was real, which is #96 — a master that refuses the SOA probe was
treated as one that is not there. **#81, #82 and #84 closed that day**; #81's and #82's remaining
sub-items went with them (81b, 82a), and #84's own remainder is named in it
rather than left as a sentence (§18).

**#85 through #90 came out of a second architecture review on 2026-09-20**, this
one asking what the ideal shape would be and where the tree differs. **Ten
findings, six rows**, and what happened to the other four is the half worth
reading:

- **The two UDP loops are duplicated on purpose.** #30's "What must not be
  unified" decided it — a fixed worker pool against a task per datagram, with
  #27b's 1 536 bytes behind the first — and the admission sequence they share
  *is* `ServeContext::allow_source` + `accept_packet`, composed per site so the
  differences stay visible. The finding was written before that page was read.
- **An `rdns-ops` crate is #82a**, already declined there on a package count.
  The rebuild measurement 82a asked for and said nobody had taken is now taken,
  in place, and agrees.
- **The reload seam in `rdnsd/src/main.rs` is #83**, which already carries the
  same count this review re-derived: #20 declined the move on nine reach-backs
  into `main`, and there is one.
- **`handle_query`'s 432 lines are answered** by `finish_dns64`'s own header,
  which names §7's epilogue hazard and says why the split is deliberate. Folded
  into #88 as context rather than filed, because the measurement is what would
  decide it.

A fifth was cut to two thirds: `ZoneError` cannot leave `rdns-core`, because
`rdns-present` uses it and does not depend on `rdns`. That is #86's own
refutation and is recorded in it.

What the review got right about the tree is a negative result: `rdns`'s 40
modules have 70 production cross-module edges and **zero cycles**, fan-in
concentrated on `error` (23) and `zone` (14). Splitting that crate is a
packaging question, not a comprehension one — which is why #85 and #86 are the
only two pieces of it worth money.

**#73, #74, #75 and #76 were filed and closed the same day**, out of an
architecture review that asked what the shape of this code costs a reader rather
than what it gets wrong — and found three defects on the way. #73 is the one on
the wire: a denial's TTL was MINIMUM alone where RFC 9077 §3 says the lesser of
MINIMUM and the SOA's own TTL, so for a zone whose SOA TTL is the smaller, every
denial outlived the SOA beside it — which this tree's own RFC 8198 cache is the
other half of. Every fixture here is `$TTL 3600` with `minimum 300`, the masking
direction, which is §1 arriving through the fixtures rather than the assertions.
#74: `--check-config` printed "encrypted transports disabled" for a DoH-only
server, because a second copy of a banner was written where the right function
existed and could not be reached. #75: `record_dnstap` sat behind `finish`, which
the transfer and UPDATE branches returned past, so a capture held neither while
two `MessageType` arms had been written for nobody. #76: three copies of
`ScratchDir`, two of them citing a reason that stopped being true at #66c — and
each citing the other.

**#77 through #84 were what the same review turned up and did not fix**, one
number per thing rather than a list in prose (§18). **#77 — #73's and #75's own
remainders — closed 2026-09-19 and 2026-09-20**, and 77a is the one worth
reading: the survey it asked for came back "every implementation fixes it in
its signer",
and RFC 9077 §§3.1-3.3 put the MUST on the TTL "that is returned" anyway. The
field and the specification disagree, and `rdnsd` is the case that decides it,
being both a signer and a server for zones it did not sign. Three rows in #78
and most of #79 were the review's reading rather than a measurement taken here;
all of them were re-checked against the code before being acted on, and all of
them held.

**#72 closed the day it was filed**: seven allocations a record on the zone load
path, not the two it
named, and after 72a and 72b a zone of A records parses with none at all — 480
ns a record to ~263. **#57 is
closed**: 57e was the last of it, and the measurement that
could have refuted it did — IXFR as this tree had it was *slower* than a whole
transfer, because applying forty records to a million-record zone cost 1 018 ms
building a key per record of the *base*. What the row was actually missing was
smaller and older: the refresh had no SOA probe at all, so an unchanged feed
cost a transfer and a reload every REFRESH. **#71 was what was left after both,
and it was neither the wire nor the format; it closed 2026-09-19.** **71b closed 2026-09-16** — a reload
keeps every feed whose file did not move, so a three-feed set costs 781 ms for
one publication where it cost 2 200, and a quiet SIGHUP 62 ms. **71c closed the
same day**: three of the four sites that rebuild a zone never got #61b's
`reserve`, which is 793 ms to 445 on the one 71a is filed against. **71d closed
2026-09-17**: the index keyed every name on a `Box<[u8]>` because a `HashMap`
reaches its key only through `Borrow` — an artifact of the collection, not of
`Name` — so `hashbrown::HashTable` and one arena took `Zone::clone` from 318 ms
to 120 and a query miss from 114 ns to 76, at zero packages. **71f closed
2026-09-18 and is the largest number this row had**: the install wrote the file
and then *parsed it back*, re-deriving a zone the process was still holding —
1 141-1 261 ms to 526 at a million rules, on a digest `rdnsd`'s UPDATE path has used
since #64b and on an equality that turned out to be asserted nowhere — the
assertion cited for it compares record *counts*, which is §4 arriving in a
row's evidence rather than in its code. The sentence calling that row "shape A's trade and not a defect" is struck
in place, because reading it as a trade is why it sat. **71a closed
2026-09-19**: a delta is applied to a *copy* now rather than rebuilt from one,
**386.9 ms to 146.3** at a million rules and the whole IXFR round trip 402 to
149 — and it is not the tombstones the row named. An index entry counts the
names directly below it, which is what makes a name removable at all without
turning a NODATA into an NXDOMAIN, and `swap_remove` leaves exactly one stale
position, which the index reaches by that record's own owner name.
`Zone::records` is untouched and no public signature moved. What its refuting
measurement found is that the index is append-only, so applying deltas forever
grew a zone that was not growing — 4 000 changes to a 1 000-name zone took the
arena from 24 031 octets to 120 031 with every answer unchanged — and a rebuild
when removals reach half the record count bounds it.

**71e closed the same day and #71 with it.** A zone keeps every owner name in
one arena and every RDATA in another, so a copy is a memcpy and **six**
allocations rather than two million: `Zone::clone` **97.6 ms to 18.7**, and the
apply 71a had left at 143.4 ms is **44.3** — 801 as the section was filed. The
answer path's whole answer went **−6.1%** with it, the lookup alone **+5.4%**,
and a parsed million-record zone holds 18 MB less. Its blast-radius figure was
the one thing it got wrong: 98 errors was measured by *sealing* `Zone::records`
where the change had to *replace* it, and a `Records` view with `len`, `iter`
and `IntoIterator` came out at 66. **#72** came out of it — filling an arena
from an owned `ZoneRecord` copies what the caller just allocated, 50 ms a
million records against the 79 ms a million every copy stops paying. It was
right about the count and wrong about which: seven allocations a record, not
the two it named, and the largest of them is one line of `Zone::add_record`
itself.

Four by-products worth the trip: `rpz_install.rs` had no turnstile, so every
number #57e and #71 recorded was taken with two other million-rule measurements
running (#64b's defect, found twice); Linux clippy caught a lint the Windows one
does not have, on a change touching no `cfg`-gated file (§1 paying out
sideways); the hand-rolled collision chain 71d started with had a bug that
`bench_zone_lookup` caught on its first run, after the logic had been read
through twice and called correct (§19); and two `usize`s added to `Zone` took
`xfr::Refresh` from exactly 200 bytes to 216, past clippy's variant threshold —
the only thing in this tree that says a field added to `Zone` is a field added
to every enum carrying one by value. **#64 is closed** — 64c, 64e and 64f
all went the same day, and 64c is the one whose remedy was declined on its own
re-measurement; **64g closed with it**, and its own filing was the thing it
refuted — the "core type's shape and its call sites" it was not taken for is a
default type parameter and zero call sites. **#68 stays open and both of its
guesses are gone**: the
accept-before-connect race it named cannot happen (the listener is bound before
the loop is spawned), the test it names has no wall-clock assertion, and
ephemeral ports are not scarce here — a whole `--workspace` run adds ~100
`TIME_WAIT` sockets to a 16 384-port range. 900 runs under load did not
reproduce it. What was fixed is that the failure left no evidence, and what it
found on the way out is ~~**#69**~~ **#69, closed the same day it was filed**
(four accept loops treated any error as fatal while the UDP side had a helper
for exactly that; the remote provocation the row leaned on turned out not to
exist, and `EMFILE` — which needs no remote party — took the whole server down)
and ~~**#70**~~ **#70, closed 2026-09-16** (the metrics header claimed two
hyper behaviours hyper does not have; the half worth having is enforced here
now, and §3.2 turned out to be three MUSTs hyper answers 200 to).
**#66 and #67 closed the day they were filed**, together: `rdnsc` transfers a
zone, signs it, verifies every envelope and writes a loadable file, and the
crate line moved twice to let it — `rdns-present` for the format and
`rdns-tsig` for the MAC, both measured against the alternative rather than
argued.
**#61 closed the day it was filed**: the reload is 3.76x faster and holds
68 MB less per million rules, and rayon was measured and declined.
**#62 closed the day after it was filed**, all three rows. 62a was the one on
the answer path: a 50 000-rule feed cost 144.6 us a query and costs 7 ns, and
the structure the row would have named had it named one was measurably the wrong
structure. 62c was the startup hang — a top-level
`$ORIGIN` per section reindexed the whole zone, 13.64 s for 16 000 records with
one before each and 12.0 ms now — and it found a second cost nobody had filed:
`reindex` rebuilt the denial chains under a comment claiming they move with the
apex, which they do not.
**#63 was filed out of 57d** and is the prerequisite 57d had been naming in
prose: `rdnsr` had no config file, so there was nowhere to write a per-zone
anything. It does not wait on 57d — `--rpz-policy` has wanted the same file
since before 57 existed. **63a is answered**: the split is about **18** items
and not the 84 the row counted, measured by sealing the file and letting the
compiler name what `rdnsd` could not do without. On the way it found **63e**,
sixteen settings whose default was written once in `config.rs` and again as a
clap literal with nothing tying them, under three comments naming the hazard
and none holding it — **closed the same day**, both sides reading one function
now — and **63f**, the same bare-`pub` sweep for the `cfg(unix)` file Windows
cannot compile, **also closed**, where the same method said 9 of 9 rather than
18 of 84: `Control` is a struct `main.rs` builds and every field is an
argument. `rdnsd` has no bare `pub` left. **63g is the other half of 63a's
question** and kills the option 63a was framed around: `rdnsr` would name **0**
of those 18, because every one is zones, signing or catalogs. What it wants a
piece of is the private `Server`, 22 of whose 34 keys it already has as flags —
so the open decision is a second parser against a split `[server]`, and the
only code genuinely shared is `read_secret_file`. **63h built both, and a third
the two of them named**: the split `[server]` is out — flattening a shared
struct costs a config error its line number and its expected-key list, for
`rdnsd`'s existing file as much as for the new one — and what landed is the
macro shape: c8ac8eb, b7c62a3 and 1e511d0, with A and B kept as branches for
the measurements behind the choice. **63j closed 2026-09-15 and #63 with it**:
`[[rpz.feeds]]` gives each feed its own policy, which costs the match path
nothing because `PolicyZone` has held one since 45a — the measurement the row
asked for first was a `grep` — and `rdnsr --check-config` landed beside it,
finding two things read below the binds that a dry run has to reach. **63i came out of the same counting
and closed the same day**: `--dnstap-max-bytes` was the one flag of 35 not
refused beside `--config`, so the file overwrote it in silence, and what
replaced the missing conflict is a test that asks clap for the set rather than
a list somebody keeps.
**#64 came out of asking 57d's question of `rdnsd`**: if a zone file is both
the interchange format and the store, what does mutating it cost? One UPDATE was
five O(zone) passes and 1.8 s on a million-record zone, under a process-wide
lock. The row was filed with the measurement that refuted the fix it was going
to propose. **64a is fixed** — four passes and 1.7 s, and it was three
clones and not the one the row named. **64b is closed**: read the file's
bytes every time, parse them only when they are not the bytes this server last
wrote, which is **38% off an unsigned update** at a million records. Its
headline number had not reproduced, and what did not reproduce was the
benchmark — one filter selected two million-record benchmarks and libtest ran
them at once. **64d is closed and answered the question
the other two were waiting on**: signing is 88% of a signed update, so 64b and
64c together are worth 10% of one rather than the 68% they are of an unsigned
one — and the measurement filed **64e**, which is that carrying every signature
forward still costs 10.3 s at a million records with no crypto in it. **64e is
split to the bottom**: six passes and not the four it named, and the largest,
`sign_everything`, splits again into three of which the signing loop is 24% of
everything and holds the four ECDSA operations. What a remedy would have to
address is now a number — 31% to build and free the carry-forward index, 24%
to probe it and `Layout` once per RRset — and it is the two maps keyed by a
name, not the chain and not the crypto. **64c, 64e and 64f all closed
2026-09-16**, and **64g the same day**, which closes #64 entire. 64f: a reload keeps the zone
it is serving for a file nobody touched, 11.4 s to 39 ms at a million records,
on the condition `ProvenSigning` already computes. 64e: the two structures it
named and nothing else, three shapes built and measured, −14% on an incremental
sign and −16% on a signed UPDATE. 64c: the measurement that could refute it
went first and did — more than half of its 42% was the *serializer*, which
built RFC 3597's hex form for every record and discarded it, and `to_string`
fell 636 ms to 250 with the file exactly as authoritative as before. The design
half is declined on what is left of it.
**#65 came out of asking 64e's question of the load path and closed the same
day**, the shapes built and the recommended one declined. The reason for asking
was refuted first — a full sign is 84% ECDSA, so a remedy in the structures is
capped at 16% — and what the measurement found instead was that
`ZoneSigning::apply` re-signed every zone from scratch at **every** load, a
SIGHUP included. A reload carries forward now, except the re-signing timer's,
which reloads *in order to* refresh. The option the row recommended was keyed on
signature age and does not work at all: the expiry spread is a fifth of the
validity and the interval a third, so every signature crosses any threshold in
the same tick. Its only remaining half is C, which is now **#64f** — 64b
answered the question and not the reload path that shares it.
**#44 and #45 are both closed in full, and so are #48, #49, #51, #53, #54 and
#55**, which is everything 44a, 44f and #50 left.
~~**None of them is a live defect**~~ — **that claim was wrong about #47**,
which closed the same day carrying two MUSTs it had been filed as not
breaking: RFC 6891 §6.1.1's OPT in a response to a request that had one, and
RFC 3225 §3's DO bit, dropped on the first envelope of every AXFR. It was filed
as "not a defect" because its own row read §6.1.1 as "asks for", and the section
says what the difference cost. Of what is left, #50 was the live one, and
closing it is what added #53 — a zone this server signed itself verified again
at every load — which closed the same day it was taken.
#57 is what is left of what 45a left — **#56 closed the same day it was filed**,
and what it found was in a cache nobody was looking at rather than in the
resolver's return type. **All five of #57's items are closed**: a reload
re-reads every `--rpz` file, runs off the worker threads, and can be asked for
by a NOTIFY from a listed address. **57d is taken** — shape A, `rdnsr` transfers a
policy zone into the file it reads, with `on-expire` per feed — and **57e closed
it on 2026-09-16**: a refresh probes the master's serial before anything else
and asks for the difference from the version already in force, which is
`PolicyStore`'s copy rather than a second one. **57f and 57g closed with it** — 57g was
wiring rather than a metric, since a policy feed is a replicated zone and the
gauge for one already existed. Under 57f a feed's master names a key with
`#name`, resolved at startup so an undefined one stops the process, and the
secret reader that would have been its third copy is `persist::read_secret`.
**Both shapes were built first** — `57d-shape-a` and `57d-shape-b` — and the
install they differ over, 1 894 ms against 32.8 at a million rules, turned out
not to be what decided it: memory is the same either way, and A was taken on
persistence. **Which way EXPIRE fails** is answered with a per-feed
`on-expire` defaulting to `enforce`. Before all this the two-process path
answered that one by accident — `withdraw` takes an expired zone out of `rdnsd`'s zone
map and leaves the file, so `rdnsr` goes on enforcing it with no age for it
anywhere. #58 is what 45b left, #59 what #51 left and #60
what #51 turned up on the way; and #21 is an inventory of deliberate deviations
rather than a queue. **#66 and #67 were filed out of 57d on 2026-09-15**, from
the question that row never asked — what an operator who wants only a resolver
actually runs, which today is `rdnsd` as a download client for `rdnsr`. #66
teaches `rdnsc` to write what it already transfers correctly, **and the owner
decided the same day that it gets TSIG**: 5 packages and, the part that is not
a count, a C toolchain in its build. #67 is the consequence — the first thing
that is not a daemon now links crypto, so where the crate line belongs is a
measurement, **taken the same day, swept module by module, and 67a-c landed**:
almost every heavy edge in `rdns` was incidental, and undoing the three that
mattered took the free set from 9 of 41 to **23**, for no package and no
binary. What the measurement itself said: `rdnsc` linking `rdns` outright would cost
+38 packages and 47% of its binary, so that is out; the tangle inside `rdns` is
one edge and costs nothing; and the figure that would decide a split needs 66a
to exist, so **66a goes first and #67 finishes after it**. **#60 closed 2026-09-14**: 19 flattened messages put back
on their `\` continuations and a test that will not let a twentieth in, and the
row's own count of 21 across 12 files did not reproduce — three of its files
hold nothing at all, one of them the false positive the row had predicted.
**#58 is lettered now and 58a is closed**: the latency histogram reaches
seconds instead of 50 ms, and the split it needed turned out not to be a
bucket at all — `dns_slow_resolutions_total` tells a slow
resolution that answered from one that failed, because the second serves stale
today and only the first is the feature's case. The row's own remedy was the
wrong one, which is the mistake `CLAUDE.md` §18 names. 58b and 58c wait on the
number, and the number wants a deployment. **#59 closed 2026-09-16 on the
prerequisite #54 left it**: a peer certificate hangs off `validation::Arrival`'s
encrypted variants and nowhere else, so a transfer over plain TCP cannot be
authorized by one. Everything else numbered is
closed; the table under "Closed work" says which, when, and where the
reasoning went.

**This sentence goes stale faster than anything else on the page** — nine times
by the page's own count, and the record is in `docs/CLOSED_WORK.md` under "How
the queue kept going stale". It used to be corrected the way a wrong *claim* is,
by striking the old one through and writing the next underneath, and by
2026-09-12 that was eleven struck restatements of a fact the table already held,
two of them nested into markdown that no longer rendered.

So the chain is gone and the table is the authority. The distinction that
survives is the one `CLAUDE.md` §11 actually draws: a claim that turned out to
be **wrong** keeps its strike-through and its correction, because the reasoning
that produced it is why the bug happened — the measurements under "Current
state" are all of that kind and are untouched. A status line that merely stopped
being current is not that, and deleting it loses nothing the table does not
hold.

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
count is 0 again. The eight commits it carried are all of #37. ~~The *reading*
half stays open and stays the owner's: there is no `gh` on this machine, so a
session cannot open a run from here at all.~~ **Wrong on both counts, 2026-09-11**:
reading a run is not pushing one — it starts no job and costs no minutes — so it
was never the owner's call, and the tooling to do it was there. All seven jobs
are read below.

**A count in a preamble goes stale whenever the list under it changes**, which
happened to this page's summary paragraphs at least ~~eight~~ ~~nine~~ **ten**
times between 2026-07-30 and 2026-09-06 — the ninth is the
`docs/CLOSED_WORK.md` section count above, found wrong on 2026-09-06 and already
wrong on the day it was written. The record is kept under "How the queue kept
going stale" in `docs/CLOSED_WORK.md`, because the shape is the lesson.

**Two remedies have been tried.** The first was a *shorter list*: two items
cannot drift from a summary of two items. That held while the list stayed at
two, and then four days of filing and closing turned the summary into eleven
struck restatements of itself. The second, on **2026-09-12**, was to *delete the
chain* — the summary above is one sentence now, and the table under "Closed
work" is the authority it points at.

The reasoning for the change is the reasoning §11 gives for the opposite: a
strike-through is kept because it preserves *why a claim was wrong*. A status
line was never wrong, it merely stopped being current, so striking it preserved
nothing the table did not already hold — while costing every reader the whole
history of a fact they had come to look up the current value of. The five wrong
claims below are a different thing and stay. Whether *that* distinction holds is
a question for the next reader who finds this page wrong.

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
# `rdns/benches/answer_path.rs` first: one whole answer is ~0.5 µs and the
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

**#58**, **#68**, **#81**-**#84**, **#90**, **#92**, **#93**, **#94**,
**#95**, plus **#21** —
see "What is open" above, which is the same list and the only place it is
written down.
Every closed section lives in `docs/CLOSED_WORK.md` under its own number; the
numbers are stable identifiers referenced from the code, so they move rather
than being renumbered.

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
whole answer is 522 ns and one `sendto`+`recvfrom` pair is 3.6-4.1 µs, so the
entire benchmark suite covers about 6% of what a query costs — the context that
stops a 20% win in it being reported as a 20% win.

---

### 57. A policy zone arrives as a file, not as a transfer — **filed 2026-09-13, closed 2026-09-16**

Also left behind by 45a, and the half of its own row that did not survive
contact with the code. #45a said the pleasing part was the delivery mechanism —
"an RPZ *is* a DNS zone, so the AXFR/IXFR/NOTIFY machinery that already exists
is how the policy would arrive". The machinery does exist. It is in `rdnsd`:
`rdns::secondary`, `rdns::transfer`, `rdns::notify`, `rdnsd/src/replication.rs`.
`rdnsr` has never been a secondary of anything, has no zone map, and ~~does not
listen for a NOTIFY at all~~ — **it does since 57c, which is what closed the
delivery half without `rdnsd` changing at all.** It is still not a secondary and
still has no zone map.

So `--rpz` takes a path, and a feed is refreshed by whatever writes that path —
which is how an operator with one feed and a cron job already works, and is not
how an operator with an hourly-updated blocklist wants to work.

Five items, all closed. 57a-c were the delivery half, 57d the transfer, 57e the
refresh that only asks for what moved.

- **57a.** ~~**Re-read before replicate.**~~ **Done, `rpz::PolicyStore`.** SIGHUP
  re-reads every `--rpz` file, all-or-nothing, and a feed that will not parse
  leaves the previous set in force with a WARN naming it. The shape is
  `CertificateStore`'s (§7): paths, an `RwLock<Arc<PolicyZones>>`, and a
  `reload` that builds the whole set before installing any of it.

  One thing the row got wrong: "`rdnsr` already has a reload signal for the TLS
  certificate, so this is a second thing that handler does" — the handler was
  spawned *inside* the `--tls-listen` arm, so a resolver with `--rpz` and no DoT
  had no reload task at all. It is now one task, spawned when either has
  something to re-read.

  **What it decided about the caches.** Only a nameserver trigger can be
  bypassed by something held: a QNAME or `rpz-client-ip` rule is consulted
  before every cache and an `rpz-ip` rule is applied to what leaves, so both
  bind the next query whatever is cached, while `rpz-nsdname` and `rpz-nsip` are
  asked only while a delegation is walked — which a cache hit never does. So a
  reload clears all three caches, and only when a zone carrying one of those two
  is at a new SOA serial. The serial, because that is the zone's own claim to
  have changed and the same number a secondary transfers on; the alternative,
  clearing whenever any nameserver rule exists, makes an hourly SIGHUP an hourly
  cold cache, which is its own outage. A file edited without a serial bump is
  missed here exactly as a transfer would miss it.

  Cost, measured on the development machine: one `RwLock` read and one `Arc`
  clone per query, **15.9 ns** in release — one snapshot decides one query,
  because the nameserver triggers are borrowed across a resolution and no lock
  may be held over that (§9). Against the 522 ns `benches/answer_path.rs` reads
  for a whole answer and the 3.6-4.1 µs its header gives for one
  `sendto`+`recvfrom` pair. No benchmark covers `rdnsr::answer::handle_query`,
  so that number is a probe rather than a bench: 20 M calls to
  `PolicyStore::in_force`, timed, not kept.

  Proved against a process, not only against the functions (§4): `rdnsr` run
  with `--rpz`, queried, the feed rewritten, `kill -HUP`, queried again — the
  new rule blocks, the cache-clear line appears when the nsdname rule arrives,
  and a feed replaced with rubbish leaves the block in force with the file and
  line in the WARN. That run is also what caught the banner defect below; the
  unit tests could not, since they assert on rcodes rather than on log lines.

  Six tests, three in `rdns::rpz` and three in `rdnsr::answer`; every one was
  run against the shape it forbids. The all-or-nothing pair fails against a
  `reload` that installs file by file; the cache pair fails against a
  fingerprint missing either half (the serial, or the "watches delegations"
  filter); the two answer-path tests fail against a `reload_policy` that returns
  at once, which is what the tree did before.
  **An unrelated defect, five instances, fixed in the same sitting.** Moving
  the banner line showed it printing `client-ip,              0 response-ip`:
  a `\` continuation had been lost from the format string and the next line's
  indentation was baked into the message. §12 names this exactly — rustfmt does
  not touch string literals, so a careless search-and-replace wrecks the
  continuation and nothing complains. `grep` for a run of five spaces inside a
  `tracing::` format string found five, in `rdnsr/src/answer.rs`,
  `rdnsr/src/main.rs`, `rdnsd/src/catalog.rs` and `rdnsd/src/zones.rs` (two);
  all five fixed, seven continuations restored.
- **57b.** ~~**The reload runs where a query is answered.**~~ **Done,
  `rdnsr::reload`.** Not part of the row as filed; found by measuring 57a rather
  than by reading it. `reload_on_signal` called the synchronous `reload_policy`
  straight from its async task, and `#[tokio::main]` gives one worker per core,
  so the parse occupied one. Measured on the development machine, release, with
  a probe asking for 1 ms ticks while a 1M-rule feed reloaded:

  | workers | reloads | worst tick, Linux | worst tick, Windows |
  |---|---|---|---|
  | 1 | 0 | 2.17 ms | 15.9 ms |
  | 2 | 0 | 2.17 ms | 16.3 ms |
  | **1** | **1** | **2.715 s** | **2.702 s** |
  | 2 | 1 | 2.28 ms | 16.8 ms |
  | 4 | 1 | 2.26 ms | 16.7 ms |
  | **4** | **4** | **3.53 s** | **3.20 s** |

  The no-reload rows are the floor the platform's timer imposes, and are why the
  Linux column exists: Windows' is ~16 ms, coarse enough to hide the two-worker
  case entirely. So a single-core resolver answered nothing for the length of a
  reload, and above one core it cost 1/N of capacity. The work is now on
  `spawn_blocking`.

  **The two bold rows are the length of a reload, and #61 made a reload
  shorter** — 2.74 s to 0.952 s at a million rules. The probe has not been
  re-run, so no number here is restated; what the table still shows correctly is
  the *shape*, which is what it was taken for and which no speed-up removes.

  The last row is the one that gated 57c: four concurrent reloads stalled every
  task for 3.53 s and took 4.50 s to do 2.70 s of work. Reloads are therefore
  serialised — one task, awaiting each — and requests coalesce onto a single
  `Notify` permit, so a burst asks for one re-read and not one per request.

  Its regression test is `a_reload_does_not_stop_the_only_worker`, and **the
  first version of it passed against the defect**: `block_on` drives the test's
  own future on the calling thread, so the one worker under test was never the
  blocked one. Both halves are spawned now, which is also how `main` runs them.
  `CLAUDE.md` §1 — the test agreed with the code until it was run against the
  shape it forbids.
- **57c.** ~~**Then the transfer.**~~ **The delivery half is done,
  `--rpz-notify-from`.** ~~The reload above leaves exactly one gap: nothing
  sends the SIGHUP. `rdnsd` has no post-transfer hook, so today the trigger is
  the operator's — a systemd path unit, or a cron job beside the one that
  already writes the file. A hook is a smaller change than a replication task
  and would settle this row without it; measure that before building the
  task.~~

  **Wrong about `rdnsd`, and the hook was never needed.** `rdnsd`'s secondary
  path ends at `announce_transfer` (`rdnsd/src/replication.rs`), which sends a
  NOTIFY to every `--also-notify` peer after every transfer — a post-transfer
  hook for anything that listens, already shipped, per zone, signed if the peer
  names a key. The gap was never on the sending side; it was that `rdnsr`
  answered NOTIFY with NOTIMP. It now has the ear, and `rdnsd` needed no change
  at all.

  `--rpz-notify-from` is a list of addresses and prefixes, parsed by the
  `TransferAcl` the query-rate exemptions already use. Naming nobody leaves a
  NOTIFY answered NOTIMP, because then the resolver really does not implement
  one; naming somebody with no `--rpz` is refused at startup. From a listed
  address, naming a zone a feed carries: NOERROR and a re-read *queued* (RFC
  1996 §4.7 wants the reply before the work, and the work is seconds). From
  anywhere else: REFUSED. For a zone no feed carries: NOTAUTH — distinguished on
  the wire and not only in the log, because the operator who can act on it is on
  the sending side.

  **The serial in the message is not read**, though §3.7 offers it. It is
  unauthenticated, and the only thing it could do here is let a re-read be
  *skipped*, so a spoofed one would suppress a real update — the failure the
  path exists to prevent. `rdnsd` ignores it for the same reason and settles the
  question against the master; here the file is the master.

  Six tests, each run against the shape it forbids: the outcome three against an
  absent ACL and an absent zone check and against the pre-change NOTIMP path;
  the serial one against a handler that compares serials; the coalescing one
  against a counting semaphore. **One claim did not survive being checked**: the
  refusal test was filed saying it proved the address is checked *before* the
  zone. Swapping the two changed no reply, because the expensive thing is the
  re-read and that is gated on the address either way — the order is still right
  (`CLAUDE.md` §16) and the test does not demonstrate it (§19).

  Proved against a process on both platforms, not only against the functions
  (§4): `rdnsr` started with a feed, queried, the feed rewritten, a NOTIFY sent,
  queried again — the new rule blocks; an unlisted sender gets REFUSED, an
  unknown zone NOTAUTH, a feed replaced with rubbish leaves the block in force.
  On Linux the same run also sends SIGHUP, which is the `cfg(unix)` arm Windows
  never compiles. **Windows had no reload trigger before this**: `next_reload`
  is `pending()` there, so a NOTIFY is the only one it has.
- **57d. What is left of the transfer — taken 2026-09-15, shape A.**

  **The argument that decided it arrived after the row was written.** 57c gave
  `rdnsr` an ear for a NOTIFY; what it does with one is queue a re-read of the
  *files*. So if nothing fetched, the
  re-read is a no-op, and the publisher's "it changed" is only meaningful when
  `rdnsd` — or a cron job that happened to run — did the fetching. **The
  resolver accepted a signal it could not act on.** That is what 57d closes,
  and it is a better reason than either figure the shapes were compared on.

  A rather than B on the row's own conclusion: the install cost is not what
  decides this and persistence is. The file survives a restart, so a resolver
  that transferred a blocklist yesterday begins today with yesterday's rules
  rather than none, and `Readiness::ready()` keeps meaning what it says. B's
  57x is real and buys nothing here — 1.9 s on a blocking thread at an hourly
  cadence is 0.05% of a core.

  Landed with the remedy above rather than after it: `on-expire` per feed,
  defaulting to `enforce`, refused without `master` because a feed nobody
  transfers has no contact to lose (§15 — a setting that cannot act is a
  setting the operator believes is in force). The age it fires on is the task's
  own `last_contact`, which is the only one this process has. Lifting removes
  the file and asks for a re-read, so one feed stops being enforced without
  disturbing the others; both directions WARN once on the transition, and
  coming back into contact WARNs too, because the lifting did.

  **What is not done: 57f, TSIG.** `MasterSpec::key_name` wants a keyring and
  `rdnsr` has none, so a transferred feed arrives unauthenticated. Cheap now
  that `rdns-tsig` is a crate (#66c) — the work is a config table and a keyring,
  not a dependency — and a blocklist fetched without authentication is worth
  the row rather than a sentence in a module header (§18).

  **What is still owed for `enforce` being the default** (§14): the feed's age
  is inside the task and nowhere an operator can see it. A per-feed gauge on
  `rdnsr`, `Option`-shaped so a feed that never transferred reads `absent()`
  and not 1970, is 57g.

  The row as it was written, kept because two of its claims did not survive
  being built — it asked whether `rdnsr` should replicate a
  policy zone itself rather than read what another process wrote. The arithmetic
  is free — `xfr::fetch_zone` returns a `Zone` and `rpz::PolicyZone::new` takes
  one — and the cost is a replication task, three timers, an EXPIRE, and a state
  sidecar, which is what `rdnsd` is.

  **Gated on a prerequisite outside this row.** A transfer spec is per zone
  (master, key name, TLS anchors); `MasterSpec` carries four fields and `rdnsd`
  spends 1 402 lines of `config.rs` on 84 public items to express that. `rdnsr`
  has 39 flags and no config file, and `--rpz-policy`'s own doc comment already
  concedes the point for a smaller thing. So 57d is a decision about `rdnsr`
  config before it is a decision about transfers.

  **That prerequisite is #63 since 2026-09-14**, because naming it here and
  nowhere else is how it stayed unscheduled (§18). #63 also checked the thing
  this paragraph assumes and found it too weak: the `--rpz-policy` concession is
  not "a smaller thing", it is a second and older demand for the same file,
  live in the tree with no 57d near it. So #63 does not depend on 57d being
  taken, and 57d is not the argument for it.

  **The three shapes** — read off the code rather than guessed. **A and B were
  built on 2026-09-15 and the numbers are below**; the inventory is kept as it
  was written, because two of its claims did not survive being compiled.
  **A**: transfer, write the zone file, let the existing reload re-read it;
  nothing in `rdns::rpz` or the answer path changes, and it pays
  `PolicyZones::load` at 0.633 s per refresh at a million rules, plus a
  serialization nothing has measured, to reparse what it just held. **B**:
  transfer straight into `PolicyZone::new`, which is 41 ms on that feed — but
  `PolicyStore` is paths-or-nothing today (`paths: Vec<PathBuf>`, and
  `in_memory` hardcodes an empty one, so `is_configured()` is false and
  `reload()` re-reads nothing), so a set mixing file feeds with transferred ones
  does not fit at all and the type has to become a list of *sources*. **C**:
  decline, which is what is shipped. ~~B is the only one 57e is worth anything
  under, because `fetch_changes` takes a `&Zone` base and A throws that base to
  disk.~~ **Wrong, and 57e is what showed it (2026-09-16).** A does not throw
  the base away: it writes it to a file the reload reads straight back, so the
  parsed zone is in `PolicyStore` the whole time and a refresh asks it for one.
  The sentence reasoned about the *transfer task's* locals instead of opening
  the process's state (§4). What it was right about is that the base has to
  exist somewhere, and under A it costs nothing because the answer path already
  needs it.

  **One consequence none of the above had noticed.** `rdnsr` passes
  `Readiness::ready()` under a comment saying "a resolver has nothing to wait
  for". Under 57d it would have something: a resolver enforcing a blocklist it
  has not transferred yet is answering with the policy not in force. That is
  `rdnsd`'s `/readyz` latch arriving at `rdnsr`, and it argues for A — a file on
  disk means a restart begins with the last feed rather than none.

  With 57c shipped, the two-process arrangement — `rdnsd` replicates, `rdnsr`
  reads, a NOTIFY joins them — needs no operator cron job and no new code on
  either side. **That is the thing 57d has to beat**, and it is worth saying
  that it may not be beaten.

  **The direction EXPIRE fails in is undecided, and the shipped arrangement
  decided it by accident — filed 2026-09-15.** `rdns::rpz` has no notion of a
  timer: with `--rpz` the file is the master and nothing expires. The two-process
  path does have one, and it does not do what it looks like. `withdraw`
  (`rdnsd/src/replication.rs:649`) drops the zone from the zone map, the deltas
  and the gauges; the *file* stays, and `rdnsr` re-reads files. So an expired
  policy feed goes on being enforced, with nothing logged on the side that
  enforces it — and the last-contact sidecar and
  `dns_zone_last_refresh_timestamp_seconds` are `rdnsd`'s, so the process
  applying the policy holds no age for it at all.

  Under 57d the timer arrives in `rdnsr` whether or not it is honoured.
  `draft-vixie-dns-rpz-04` §2 makes it real — "The RPZ's SOA record is real, with
  a serial number used for NOTIFY and IXFR, and timers used for AXFR and IXFR" —
  and §2 requires RPZs to "be primary or secondary zones at subscriber recursive
  resolvers", so dropping one of a secondary's three timers is a claim to defend
  rather than an omission. What to do when it fires is not specified.

  Neither direction is safe, and `rdnsd`'s answer does not transfer:

  - **Lift** (withdraw, as an authoritative zone does) silently un-blocks
    everything the feed carried, on a process that stays healthy. The trigger is
    the master being unreachable, so blackholing the publisher is an off-path off
    switch for the blocklist — and the EXPIRE it runs on is the publisher's
    number, not the resolver operator's. Withdrawal is right for authoritative
    data because serving it stale with AA set is a false statement about somebody
    else's zone. A policy zone asserts no authority, so the reason does not carry.
  - **Enforce** makes a retraction unreachable: a delisted false positive, or a
    lifted order, stays applied until a person notices. That is `CLAUDE.md` §4's
    "missing state degrades, never crashes is right for a cache and wrong for
    anything with teeth" pointed the other way, and it is defensible only with
    the age visible on the enforcing process — `Option`-shaped, so a feed that
    never transferred is `absent()` rather than 1970 (§14).

  **And "closed" cannot be derived from the zone.** The costs are asymmetric —
  lifting hits every client behind the resolver and is remotely triggerable,
  while enforcing hits the listed names and is visible to whoever is blocked —
  which argues for enforcing by default. But `Action::Passthru` and
  `PolicyOverride::Passthru` make a feed an *allow*list, and a stale one of those
  fails open for exactly what it exempts. The safe direction is a statement about
  what a feed is for, so it belongs beside `policy` in `[[rpz.feeds]]`, per feed.
  **The remedy, decided by the owner 2026-09-15: a setting per feed.** Not a
  global rule and not a default derived from the rules — both were shown wrong
  above. `[[rpz.feeds]]` gains a third key beside `file` and `policy`:

  ```toml
  [[rpz.feeds]]
  file = "malware.rpz.zone"
  master = "malware.rpz.example.@192.0.2.9"   # 57d
  on-expire = "enforce"                       # or "lift"; enforce is the default
  ```

  `enforce` keeps the rules in force past EXPIRE; `lift` withdraws the feed, as
  `rdnsd` does for an authoritative zone. The default is `enforce` on the
  asymmetry argued above — lifting hits every client behind the resolver and is
  triggerable by anyone who can blackhole the publisher, while enforcing hits
  the listed names and is visible to whoever is blocked. An operator whose feed
  is an allowlist sets `lift` and says so in the file, which is the whole point
  of the key: `Action::Passthru` means the safe direction is a fact about what
  a feed is *for*, and nothing in the zone carries that.

  **What is already true, checked rather than assumed.** `PolicyZone` has
  carried a `PolicyOverride` per feed since 45a, so the match path costs
  nothing — the same grep that answered 63j. The config shape is there: an
  `Option<String>` per field is §15's override, and `[rpz].policy` already
  shows how a feed inherits when it says nothing.

  **What has to exist first, and it is not the key.** `rdnsr` holds **no age
  for a feed at all** — no last-contact time, no `refreshed_at`, nothing; the
  sidecar and `dns_zone_last_refresh_timestamp_seconds` are `rdnsd`'s. So
  `on-expire` has nothing to fire on until the resolver knows when the
  publisher last spoke, which is 57d's transfer. **Filing the key without that
  is filing a setting that cannot act**, and the mtime shortcut is refused for
  the reason `secondary.rs` already gives: an unrelated touch resets the clock
  and a copy preserves a timestamp describing the wrong event.

  So the order is 57d first, `on-expire` with it, and neither alone. Under
  shape A the age can come off the transfer task; under B likewise — it is the
  same task either way, which is why this does not choose between them.

  **What `enforce` owes, since it is the default** (§14, §4): the feed's age
  has to be visible on the process enforcing it — a per-feed gauge on `rdnsr`,
  `Option`-shaped so a feed that never transferred is `absent()` and not 1970.
  A silently stale blocklist with no number on it is the condition this whole
  finding is about, and defaulting to `enforce` without the gauge would ship it
  deliberately.

  **What would refute the key** (§19): a deployment where every feed wants the
  same answer. Then `on-expire` is ceremony and a global setting would have
  done. The case that decides it is a feed made of `rpz-passthru` rules — an
  allowlist — and this tree has never been pointed at one. If none exists in
  the wild, the per-feed shape is wrong and the default is the whole answer.

  **A and B are built — 2026-09-15, branches `57d-shape-a` and `57d-shape-b`,
  both off `57d-measure`.** §19: arguing costs more than compiling, and what
  the build settled is not what the row expected it to.

  The measurement both turn on is `rdns/tests/rpz_install.rs`, which times the
  one thing they do differently — what happens after the last envelope arrives.
  A million QNAME rules, release, three warm runs after a discarded first,
  spread 0.4% on A's total and 5.9% on B's:

  | at 1M rules | A: into the file | B: straight into the index |
  |---|---|---|
  | per refresh | **1 894–1 902 ms** | **32.3–34.2 ms** |
  | of which | serialize 495, write 635, re-read 756 | index 32.8 |
  | installed set | 303.4 B/rule | 303.4 B/rule |
  | transient | an 85 B/rule string, plus a second copy of the zone | none measurable |
  | diff | 303 insertions, `rdnsr` only | 641, of which 211 lines of `rdns::rpz` and 129 of its tests |

  Four things the build surfaced that the inventory above had not:

  - **The row expected memory to decide this and it does not.** Both shapes
    install the same zone, 303.4 B/rule measured from the same baseline — the
    first run of the probe read B as holding nothing, which was the measurement
    taking A's parse and B's hand-me-down from different starting points. What
    actually differs is transient: A serializes an 85 B/rule string and parses
    a second copy of a zone this process had just held.
  - **A's cost is not the reload the row named.** It is the serialize-and-write
    the row called "a serialization nothing has measured": 1 130 ms of 1 894,
    60%. The re-read it did name is the smaller half.
  - **B's type change has almost no blast radius.** `PolicyZones` holding
    `Arc<PolicyZone>` changed no call site outside `rpz.rs` — the four
    `.zones()` users deref through it — and one field on `Resolving` cost six
    initializers, five of them tests. "The type has to become a list of
    sources" was right and "does not fit at all" overstated it.
  - **Both shapes needed something neither the row nor 57c had named: a NOTIFY
    wake per feed.** `PolicyReload` is one permit for the process, which is
    right when every feed is a file somebody else writes — the re-read is of
    the set, and the ACL is the bound. Once a feed has a master of its own, a
    NOTIFY from one publisher makes this resolver re-read every *other*
    operator's file, so the wake has to name the zone. Not a defect in the
    shipped tree, and it would be one the day either shape landed.

  **What neither shape settles, and why the numbers do not close the row.**
  1.9 s on a blocking thread at an hourly cadence is 0.05% of a core, so A is
  affordable for one big feed; what makes it expensive is a *set*, because the
  reload is all-or-nothing and one feed's refresh re-reads every feed. And B
  buys its 57x by giving up the only thing A has: the file. A restart under A
  begins with yesterday's rules, under B with none —
  `PolicyStore::awaiting` counts exactly that, and it is the same question as
  the EXPIRE direction above. So the install cost was worth measuring and is
  not the discriminator; **the row turns on persistence and on which way a
  stale feed fails, not on what an install costs.**

  Both branches stop short of the same two things, named rather than defaulted
  into (§18): **no TSIG** — `MasterSpec::key_name` wants the keyring
  `--tsig-key` defines and `rdnsr` has none, so a transfer on either branch is
  unauthenticated — and **no EXPIRE**, which is the question above and not a
  loop to write.

  **One claim here is not first-party and must not be quoted until it is.** BIND
  is reported to log `response-policy zone expired; policies unloaded` — to lift,
  that is — but that comes from operator write-ups; the BIND 9 ARM says a
  subscriber "must be configured as a secondary server for the zone" and says
  nothing about expiry, and BIND's source was not read. Unbound transfers an RPZ
  by AXFR/IXFR and its documentation is silent on the question; Knot Resolver's
  RPZ is file-only with a watchdog, which is the shape this tree ships. §4 wants
  the other implementations quoted, and one of the three is a rumour.
- **57e. And IXFR only if the zone is large enough to care — filed 2026-09-13,
  closed 2026-09-16.** A national blocklist is thousands of names; the RPZ feeds
  that are millions are the commercial malware ones. `rdns::ixfr` exists either way, so this is a question
  about the timer and not about the format.

  **What 57b measured moves this**, and away from the timer. Reload cost is
  linear at ~2.7 µs per rule — 1.5 ms at a thousand rules, 170 ms at a hundred
  thousand, 2.74 s at a million — which any sane cadence absorbs on two or more
  cores. Memory does not: a set is 352-407 bytes per rule held, and the reload
  is all-or-nothing, so both sets are live at once. A million-rule feed holds
  407 MB and peaks at **1.06 GB** to re-read it. Applying a forty-record delta
  should not cost a gigabyte, so if the million-rule feed is a real target the
  incremental path is required — and IXFR has nothing to apply a delta to
  without 57d. 57e therefore does not precede 57d; it is an argument for it.

  **#61 moved all three of those figures the next day**, and the paragraph above
  is kept as 57b's because the reasoning is unchanged — only the code under it
  is. Current, from #61f's table: `PolicyStore::reload` **0.952 s** at a million
  rules and **71 ms** at a hundred thousand, **339.4 bytes per rule held** and a
  **758.8** peak, so a million-rule feed holds 339 MB and peaks at **759 MB**.
  The series is no longer flat at 2.7 µs a rule either — 0.95 µs at a million
  against 0.71 at a hundred thousand, the residual drift being the 2M-entry
  index table's cache behaviour, which #61 records as inherent. **A thousand
  rules was not re-measured**, so 57b's 1.5 ms is the only figure there is for
  that size and it is now an upper bound rather than a reading.

  None of that weakens the argument. Applying a forty-record delta should not
  cost three-quarters of a gigabyte any more than it should cost one, and
  **#61's own closing note says the 2x reload peak does not go away**: per-zone
  build-then-swap buys nothing with one big feed, because "old zone + new zone"
  *is* "old set + new set", and it would only help a set of many zones by giving
  up the all-or-nothing property that is the point (§4).

  **Taken and closed 2026-09-16, and the measurement that could have refuted it
  went first** (§19). `rdns/tests/rpz_install.rs` — 57d's own harness, which
  had never been committed and which this row's module header cited anyway —
  grew a second table timing a whole refresh against a loopback master built
  from `axfr_messages` and `ixfr_response`, the two halves `rdnsd` actually
  answers with. A million QNAME rules, release, the development machine:

  | per refresh at 1M rules | before | after |
  |---|---|---|
  | the master has nothing new | 1 372 ms AXFR, then the install | **0.3 ms** |
  | forty rules changed | 1 485 ms | **808 ms** |
  | of which applying the difference | 1 018 ms | **801 ms** |
  | the install either route then pays | 1 351 ms | 1 351 ms |

  **The refutation came first and was the finding.** IXFR as this tree had it
  was *slower than AXFR* — 1 485 ms against 1 372 — so the row as filed would
  have shipped a slower refresh. `ixfr::apply_changes` built an owned key per
  record of the **base** zone (a folded name, a `Name` and a `RecordData`
  clone, three allocations) to probe a map holding forty entries, and
  `xfr::into_outcome` cloned the whole base zone before the first step threw
  the clone away, then rebuilt the zone once per version step — 32 zone-sized
  rebuilds for a client at the end of a full chain. The keys are the delta's
  now, bucketed by folded owner name so a base record is probed with the octets
  it already holds, and the steps are staged and applied in one pass
  (`ixfr::Patch`). The staging is the part that needed a test rather than an
  argument: its reference is the old behaviour, step by step, and it fails
  against a patch that stages every deletion against the base, because the
  third step of the fixture deletes what the second added.

  **And the larger cost was not IXFR at all.** The refresh had no SOA probe: it
  fetched the whole zone and rewrote the file every REFRESH whatever the
  master's serial, so an unchanged million-rule feed cost a transfer, 1 351 ms
  of write-and-reparse, and a re-read of every *other* feed. `rdnsd` has probed
  since it was written, which is §7 exactly — the shape existed once and the
  second copy is where the bug lives — so it is one function now,
  `xfr::refresh_zone`, and both daemons call it. Three tests assert which
  question went out, against a master that records them: `["SOA"]` for an
  unchanged feed, `["SOA", "IXFR"]` for a changed one, `["SOA", "AXFR"]` for a
  feed holding nothing to bring forward. All three fail against the code they
  replaced.

  **The base is the version in force**, read back out of `PolicyStore` rather
  than kept beside it: that zone is the file's contents and is already parsed
  for the answer path, so the row's "applying a forty-record delta should not
  cost a gigabyte" is answered by not holding a second copy at all. It can be
  one reload behind the file, which only means asking from an older serial —
  RFC 1995 §4 lets a master answer that with a longer chain or with the whole
  zone.

  **What is left is neither the wire nor the format, and is #71**: ~~801 ms of
  the 808~~ **the whole of the 783** is rebuilding a `Zone` whose index holds
  positions and cannot be edited — an empty difference sequence costs 793 on the
  same zone, which is the same number back — and the ~~1 351 ms~~ **1 190 ms**
  install is shape A writing out what this process already holds (**526 ms**
  since #71f, which is what happened to the half of it that read the file back). Both are
  measured there, and 71a is the same obstacle #64g and #65 reach from the
  UPDATE and signing sides.

  **Every figure this row recorded was taken under contention** and is struck
  above where #71 re-measured it: `rpz_install.rs` had no turnstile, so the
  recipe in its own module doc ran three million-rule measurements at once. The
  reasoning is left standing because it is unchanged — the shape of the row,
  that the install and the rebuild are both zone-sized and the wire is not, is
  what the numbers were for and is what they still say. See #71's head for the
  fix; #64b is where this defect was first found.

- **57f. A transferred policy feed arrives unauthenticated — filed and closed
  2026-09-15.** `[keys."partner.key."]` in `rdnsr`'s config, in `rdnsd`'s
  spelling and through `TsigKey::parse`, so the two daemons and `rdnsc` cannot
  disagree about what a key means (§7). A feed's `master` names one with
  `#name`; the key is resolved at *startup*, so a name that defines nothing
  stops the process instead of sending one unsigned request per refresh
  forever. Unsigned stays allowed — a feed reached over a private link is a
  real deployment — and what is refused is asking for a key and not getting it.
  Two doors, because a secret file that cannot be read passes the config check
  and fails the lookup: `Config::check` refuses an undefined name, and `serve`
  refuses again with the secret file named.

  No `zones` or `update-zones` beside the key, which `rdnsd`'s table has: those
  are a *server's* answer to "what may this key do", and a resolver only ever
  presents one. A scope here would be a setting that cannot act (§15, §16).

  **The third copy of the secret reader is gone with it** (§7): `ensure_private`
  then read then reject-empty existed in `rdnsd`'s config and `rdnsc`'s
  `--tsig-file`, and this would have been the third. It is
  `rdns_core::persist::read_secret` now, and both existing callers are four
  lines each.
  The row as filed, kept because it named a cost that turned out to be the
  cheap part — out of 57d, which landed without it and said so in its own
  module header:
  `MasterSpec::key_name` is looked up in a keyring and `rdnsr` has none, so
  `master = "block.example.@192.0.2.9#partner.key."` parses and the key name
  goes nowhere. A blocklist fetched without authentication is a blocklist
  anyone on the path can replace.

  **Cheap now, and it was not before**: `rdns-tsig` is its own crate since #66c
  and `rdns` re-exports it, so the work is a `[keys]` table in `rdnsr`'s config
  and a keyring beside the feeds — the secret-file reader is
  `persist::ensure_private` plus four lines, which `rdnsd` and `rdnsc` both
  already call (§7). Not a dependency question any more.
- **57g. `enforce` is the default and the age is invisible — filed and closed
  2026-09-15, and it was wiring rather than a metric.** Everything it asked for
  already existed: `DnsMetrics::note_zone_transfer`, `forget_zone`, and a
  renderer that *omits* a zone with no transfer rather than zeroing it, with the
  reason already written there — zero reads as 1970 and `absent()` is a question
  the query language can ask. `rdnsr` already builds a `DnsMetrics`. So a policy
  feed lands in the same `dns_zone_last_refresh_timestamp_seconds` an operator
  already alerts on for `rdnsd`'s replicated zones: same name, same shape, same
  PromQL (§7).

  **`enforce` and the gauge are one decision seen twice.** Keeping a feed's
  rules in force past EXPIRE is only defensible because the series stays and
  goes stale, which is what `time() - dns_zone_last_refresh_timestamp_seconds >
  EXPIRE` fires on. Lifting forgets the feed, because a gauge frozen at its last
  value shows a policy nobody applies as perfectly healthy. The test asserts
  both halves and fails in both directions — forgetting under `enforce` hides
  the alert, not forgetting under `lift` invents one.
  The row as filed: 57d's `on-expire` fires on the task's own `last_contact`,
  which lives in the task and nowhere an operator can see. §14: a per-feed gauge on `rdnsr`,
  `Option`-shaped so a feed that never transferred reads `absent()` rather than
  1970 — the same shape `dns_zone_last_refresh_timestamp_seconds` has on
  `rdnsd`, for the same reason. Defaulting to `enforce` without it ships the
  silently-stale blocklist this whole finding is about; the difference is that
  it is now on purpose and has a number.
---

### 58. serve-stale answers a dead upstream and not a slow one — **filed 2026-09-13**

Left behind by 45b. RFC 8767 §4 has two timers and this tree implements one.

The **query resolution timer** is the one in place: resolve, and if that fails,
answer from the stale window. It covers an upstream that is down, refusing, or
unreachable — which is the outage the 45b row was about.

The **client response timer** is the other, recommended 1.8 seconds: answer from
the stale window *while the resolution is still running*, and let it finish into
the cache for the next client. It covers the case a subscriber actually notices
more often — an authoritative server that is slow rather than dead, where this
resolver's own `timeout_ms` of 5 seconds is longer than a browser waits.

Why it was not done with the rest: it is not a cache change, it is a lifetime
change. `handle_query` borrows `&Resolving`, and answering early means the
resolution has to outlive the request that started it — a task, holding an
`Arc<Resolving>` and a `Busy` from `rdns::shutdown` so the drain waits for it
(`CLAUDE.md` §9: dropping a `JoinHandle` detaches, it does not cancel). That
means `handle_query` takes `&Arc<Resolving>`, and the two socket loops have to
agree about who owns the guard.

**45d moved one of those pieces on 2026-09-13.** `handle_query` returns
`Answered` now — the reply, plus work the socket loop runs *after* sending it —
and a prefetch goes down that path. What it does not solve is this one: a
prefetch starts after the answer, and the client response timer has to answer
while a resolution is already running. The return value is the same shape; the
lifetime is not.

Three things to settle, and the first is a measurement:

- **58a. How often would it fire?** ~~A resolution that takes over 1.8 s and
  then succeeds is the only case this helps. `LatencyTimer` already feeds the
  latency histogram, whose buckets stop at 50 ms — so the number is not
  currently measurable and the first step is a bucket that reaches seconds.~~
  **The instrument is in as of 2026-09-14 and both halves of that were wrong.**

  The bucket was necessary and is not the measurement. The histogram counts
  *answers*, and an answer is a cache hit at 1 µs or a recursion at 2 s with no
  way to tell them apart, and it carries no outcome — so `le="1.8"` against
  `+Inf` says how many answers were slow and nothing about whether a stale
  reply would have been the better one. The remedy the row named would have
  been filed as the number and was not one (`CLAUDE.md` §18).

  And "the only case this helps" is not right either. A resolution that runs
  long and then *fails* serves stale today — the query resolution timer does
  it — so the client response timer buys it the seconds in between, not the
  answer. The two cases are worth different amounts, which is why the
  measurement is a split and not a total.

  What landed: eleven bucket bounds instead of eight, reaching 5 s, with
  `le="1.8"` on RFC 8767 §4's number and `le="5"` on `timeout_ms`'s default;
  `rdns::cache::CLIENT_RESPONSE_TIMER` as the one place 1.8 s is written, which
  is the flag's default when the feature lands; and
  `dns_slow_resolutions_total{outcome="completed"|"failed"}`, counted at the one
  recursion a client waits on. `completed` is the feature's whole case.

  Verified by provoking it rather than by reading the diff (`CLAUDE.md` §4):
  two tests drive `handle_query` against a forwarder that sleeps 1.9 s and
  against a black hole, and both fail with the count on the wrong side of the
  split as well as with it removed. The timing is real — `LatencyTimer` is
  `std::time::Instant`, which neither this crate's test clock nor tokio's
  paused timer moves — so the pair costs 2.0 s of suite time. Scraped off a
  running `rdnsr` as well: one forwarded query rendered
  `dns_answer_latency_seconds_sum 0.028286` into `le="0.05"`, which the old
  top bound of 50 ms could not tell from a ten-second answer.

  **The number is still not taken.** An instrument is not a measurement: these
  counters have to run somewhere with real traffic, and recursion cannot be
  verified here (see "Verifying"), so the scrape above is a *forwarded* query
  and not the case 58 is about. Until `completed` has been read off a
  deployment, 58b and 58c are not worth starting.
- **58b. What stops a flood of detached resolutions?** The in-flight semaphore
  bounds tasks *per datagram*; a resolution that outlives its datagram is
  outside that bound. It needs one of its own, or the permit has to be handed
  to the task.
- **58c. Does the early answer suppress the second client's?** Two clients
  asking the same slow name should not start two resolutions. That is a
  de-duplicating in-flight table, which this resolver does not have and which
  is worth more than the timer on its own.

---

### 59. Nothing here demands a client certificate for a transfer — **filed 2026-09-13, closed 2026-09-16**

The server half of #51, which closed the client half. RFC 9103 §7.5 gives a
primary two ways to decide a transfer client is allowed: "mutual TLS (mTLS)" or
"an IP-based ACL (which can be either per message or per connection) combined
with a valid TSIG/SIG(0) signature on the XFR request", and adds "If only one
method is selected, then mTLS is preferred". This tree does the second, and has
since `security::TransferAcl` and #16. So this is not a conformance gap — one of
the two is what the section asks for — it is the half an operator who has
standardized on mTLS cannot use.

~~**It is two problems stacked, and the lower one has a number already.**~~
**One problem as of 2026-09-13**: #54 closed the same day this was filed, and
the stack is one deep now.

- ~~**The plumbing is #54's.** A certificate's identity has to reach
  `answer_transfer`, and what reaches it is `validation::Privacy` — `Clear`,
  `Tls13`, `TlsOlder` — which says what a connection hid and nothing about who
  was on it. ... That is #54's `Arrival { privacy, protocol }` with a third
  field, and #54 has already measured what it touches: 6 `Handler::handle`
  impls, 5 sites that supply the value, 30 `Privacy` sites of which 19 are test
  call sites.~~ **Done.** `validation::Arrival` is on `Handler::handle`,
  `tcp::serve_one` and `Wire::Framed`, so what reaches `answer_transfer` now
  says which protocol carried the message. A peer certificate is a field on
  `Arrival::Dot` and `Arrival::Doh` — where `Arrival::Tcp` cannot carry one,
  which is the property that decided #54's shape. `tls::serve_one_tls` is the
  one place to read it (`stream.get_ref().1.peer_certificates()`), beside where
  it already reads the negotiated version.

  **And the two numbers in the struck text were wrong**, which is why they are
  struck rather than deleted: 30 and 19 did not reproduce. Re-counted on the
  commit before #54's fix, excluding comments: **44 `Privacy` mentions across 8
  files, 10 of them `Privacy::Clear`**. Nothing touched `Privacy` in between, so
  they were wrong when written. The other two — 6 handlers, 5 supply sites — did
  reproduce. A count filed without the command that produced it is a count
  nobody can check (`CLAUDE.md` §18).
- **The decision is #16 again.** `WebPkiClientVerifier` answers "is this
  certificate one we trust", which is authentication; which zones that client
  may transfer is authorization, and a verified certificate says nothing about
  it (`CLAUDE.md` §16). `answer_transfer` authorizes against the *apex* through
  a `TsigSession`, and a certificate is not one. What a certificate maps to is
  the thing to settle before any of it: a subject name matched against a
  per-zone list, or a certificate that stands for a TSIG key's scope.

**And a third thing, which is why it cannot simply be switched on.** The DoT
listener is one `rustls::ServerConfig` shared with DoQ and DoH
(`tls::config_with_alpn`), so a client-certificate verifier on it asks *every*
querier for one, not only the ones asking for a transfer. RFC 8310 §8.2's mTLS
for DoT is a different relationship from RFC 9103's, and `tls.rs`'s header says
so. This needs either a second listener, or a verifier that allows an
unauthenticated client with the transfer path refusing what arrived without one
— which is the shape to build, and the one to measure against a DoT stub
resolver that offers no certificate.

**Taken 2026-09-16.** The shape the row named is what landed — "a verifier that
allows an unauthenticated client with the transfer path refusing what arrived
without one" — and the measurement it asked for is a test:
`a_stub_resolver_with_no_certificate_is_still_served` drives a DoT client with
no certificate against a listener that asks for one, and it fails against
`WebPkiClientVerifier::builder(..).build()` without `allow_unauthenticated`,
where the handshake is refused outright.

**What a certificate maps to, which the row said to settle first.** Neither of
the two options it named. Not "a certificate that stands for a TSIG key's
scope", because then a transfer needs both credentials and mTLS alone is not
one of §7.5's two methods; and not a subject name matched by hand, because that
is an X.509 parser this tree deliberately does not have (#42a). What landed is
the subject *alternative* name, checked by `webpki` — the same code that
verified the chain, already in the lock under `rustls`, so **0 packages** — and
`--allow-transfer-cert name[:zone[,zone]]` beside it, in `--tsig-key`'s
spelling for the same field.

- **Authentication and authorization stay apart** (§16, and #16 is the defect
  this avoids repeating): the anchors decide whether a certificate is
  trustworthy, the list decides what its holder may take, and a second
  certificate from the same CA transfers nothing until it is listed. The three
  credentials — address, key, certificate — are additive, so an operator who
  wants mTLS alone lists no addresses and defines no keys. There is no
  "require mTLS" switch because there is nothing for it to do.
- **The scope check is one function now.** `TsigKey` and the new credential
  both answer "may this take that zone", and two spellings of that is how one
  of them comes to say yes: `rdns_core::zone_scope::ZoneScope` is the answer
  for both, with the case fold (RFC 4343) and the apex-not-child rule in one
  place (§7).
- **`Arrival` carries the certificate**, which is #54's shape used for what
  #54 was built for: `Arrival::Tcp` cannot carry one, so a transfer over plain
  TCP cannot be authorized this way by construction. It costs `Copy` — 2 octets
  to 16, one `Arc` bump per message, both recorded at the assertion that pins
  the size (§17).
- **The anchor loader was already written twice waiting to happen**: `XotTrust`
  read a CA bundle for the client direction with an empty-file refusal, and
  this needed the same for the server direction. One `TrustAnchors` does both.

**What the row got wrong about its own cost.** It called the plumbing done and
the decision open; the decision took a paragraph and the plumbing took the
diff. The DoT/DoQ/DoH configurations share one builder, so the verifier reaches
all three at once — that part was as cheap as the row hoped.

**And what it was right about, which does not change** (§19): no peer exists
that will not transfer to us over TSIG. #43's harness still uses TSIG against
BIND, Knot and NSD, including 43g's transfer over TLS. This is an
interoperability gap with nobody on the other side of it today, and it is
implemented because the operator who has standardized on mTLS is the one who
cannot use a workaround.

**What would refute the value of it** (§19): that a peer exists which will not
transfer to us over TSIG. None does today — #43's harness uses TSIG for every
transfer including 43g's over TLS, against BIND, Knot and NSD — so this is an
interoperability gap with no known peer on the other side of it, which is why it
is filed rather than taken.

---

### 60. A string continuation flattened into spaces is an operator-facing defect — **filed 2026-09-13, closed 2026-09-14**

Found while writing four of them into #51 and then reading the message back off
the binary. A `\` at the end of a line inside a Rust string literal
continues it and eats the next line's indentation; a rewrite that loses the
backslash turns that indentation into the message. `rdnsd --transfer-tls-cert`
with no `--transfer-tls-ca` printed fourteen spaces mid-sentence before it was
fixed.

~~**Counted before fixing one** (§18): **21 sites** across 12 files —
`rdnsd/src/config.rs` 5, `rdnsd/src/main.rs` 4, `rdnsd/src/catalog.rs` 3, and one
each in `rdns/src/endpoint.rs`, `notify.rs`, `transfer.rs`, `zone_signer.rs`,
`rdnsd/src/control.rs`, `dispatch.rs`, `replication.rs`, `zones.rs` and
`rdnsr/src/main.rs`.~~ **Did not reproduce: 19 literals across 9 files, 30 runs
between them.** The widest is still 34 spaces (`config.rs:566`) and the rest are
14 to 30; the four this session introduced were already fixed and are not in
either count.

Three of the twelve files have nothing at all — `rdnsr/src/main.rs` has no run of
even three spaces in any literal, `zones.rs` has only a deliberate two-space
indent in a failure list, and `control.rs` has the aligned `HELP` table, which
is a correctly `\`-continued multi-line literal and is **exactly the false
positive the row's own first bullet predicted**. Three others were undercounted:
`zone_signer.rs`, `dispatch.rs` and `catalog.rs` hold 2, 2 and 2 against the
row's 1, 1 and 3. The number was filed without the command that produced it, so
nobody could check it — `CLAUDE.md` §18, and the second time in three rows
(#59's struck 30 and 19).

**And the 19 are not a sample, they are all of them.** No prose `\` continuation
survives anywhere in the workspace: every literal that spans source lines is a
zone-file fixture or an aligned table. So the idiom is not one this tree
sometimes gets wrong; it is one nothing had kept.

Cosmetic in that nothing behaves differently, and not cosmetic in the way that
matters: these are `bail!` and `serving_error!` strings, which is to say the
sentences an operator reads when something is wrong, and several are the startup
refusals that exist so a misconfiguration is a sentence rather than a silence
(`CLAUDE.md` §15).

Three things to settle, and all three settled:

- **A detector, first** — `rdns/tests/flattened_messages.rs`. Not a regex: a
  small state machine over each file that skips comments, char literals and raw
  strings, so what it measures is string literals and not source lines. It
  reports the 19 by file, line and run width, which is how the count above was
  checked.
- **Then whether it is a lint** — a test, and the worry that it would fail on
  somebody's legitimate table is answerable rather than arguable (§19). Runs
  inside a one-source-line literal come in two populations with **nothing
  between them**: 2 to 5 spaces, every one a `{:>9}` table, a zone-file fixture
  or the root hints, and 14 to 34, every one a flattened sentence. The
  threshold is six, in the middle of that gap, and it costs zero false
  positives today.

  Two exclusions do the rest of the work, and each is a reason rather than a
  heuristic: a literal written across source lines is using the `\` idiom
  already, and a literal carrying a `\n` escape is rendered output — a table,
  a zone file, `--help` — where a run of spaces is the alignment. `control.rs`'s
  `HELP` is excluded by the first and `metrics_server.rs`'s route list by the
  second, which are the two the row's bullet was worried about.

  The rejected alternative was the row's own preference, a `#[test]` over the
  *rendered* messages. There is still no list of them to render, and building
  one means provoking 19 failures in three binaries to read 19 strings back —
  more machinery than the defect, and it would miss the twentieth.
- **And it is its own commit** (§12) — one, with the test in it, because the
  test fails without the rewrite and a commit that is red is not a commit
  anybody can bisect through.

Verified by provoking three of them off the built binary rather than by reading
the diff (§4): the catalog-with-no-masters refusal, `--transfer-tls-only` with no
TLS listener and a malformed `--also-notify` spec all print as sentences.
Reverting the nine files makes the new test name all 19. The Rust detector and
the throwaway Python one that produced the first count agree on the same 19,
which is the only reason to trust either.

---

### 61. A million-rule reload spends its time building the index, not parsing — **filed and closed 2026-09-14**

#57b measured the reload from outside (2.74 s at 1M rules, 407 B/rule held,
1.06 GB peak) and left where it goes unanswered. Answered now, by ablation
against the real private functions rather than by reading the loop.

**The parse is not the cost.** At 1M rules, of 2298 ms: reading the 38 MB file
8 ms, `logical_lines` 141, tokenizing 235, owner `Name` 71, RDATA 119 — and then
`Zone::add_record` **927 ms (40%)** and `check_cname_exclusivity` **755 ms
(33%)**. `PolicyZone::new` is 41 ms; `trigger_subtree` rejects a QNAME rule and
the loop moves on.

Inside `add_record`, `note_non_terminals` is the largest single item (cumulative
sub-ablation: 99 ms for the fold and push, 423 with the index entry, 466 with
`Shortcuts::note`, **1113 with the non-terminals**).

**The per-rule drift #57b saw and could not explain** — 1.5 µs at 10k against
2.7 µs at 1M — is two hash tables outgrowing cache, and mostly not in the
parser. `check_cname_exclusivity` alone goes 685 ns/rule at 100k to 1371 at 1M.
The zone index reaches **2 M entries for 1M rules**: one per owner and one per
empty non-terminal, and hashbrown rounds buckets to a power of two, so the ENTs
double the table as well as the keys.

- ~~**61a. The checks rebuild the index they could have asked.**~~ **Done.** `CLAUDE.md` §13's
  "a scan beside the index that would have answered it", exactly:
  `check_cname_exclusivity` built a second `HashMap<Name, (bool, Vec<Rtype>)>`
  over every record — a `Name` clone and a `Vec` each — when `Zone::index` is
  already that grouping under the same fold. Asked of the index instead:
  **1371 ms -> 5.6 ms** at 1M. It is also the *memory* peak: dhat's call-stack
  profile put the global high-water mark inside it, 196 B/rule of transient,
  more than the records themselves. **Found independently by two passes, one
  timing and one allocating, which is the strongest evidence on this page that
  it is real.**
- ~~**61b. `Zone::reserve` before the loop.**~~ **Done.** `logical_lines` already knows the
  record count. Index build **743 -> 423 ms**. The hint is `2 * records` because
  of the non-terminals; `1 *` buys only 743 -> 678, and the cost of `2 *` is an
  oversized table for a zone whose names are all apex children.

  **It reached one of four call sites, and that was found two days later
  (#71c).** Nothing above is wrong: the parse is what this row measured and the
  parse is what it fixed. What it did not do is count the instances of the shape
  first (§18) — `ixfr::Patch::apply`, `xfr::into_zone` and
  `update::into_zone` all build a zone record by record, all knew their counts,
  and all three kept growing the index from empty for two more days. The "cost
  of `2 *`" caveat above is why those three got `reserve_like` instead: a caller
  holding the base does not have to estimate.
- ~~**61c. `note_non_terminals` owned what it walked.**~~ **Done.** A `&mut self` method, so
  it allocated the origin key and every ancestor to satisfy the borrow checker —
  four allocations per record. A free function over the index instead:
  **1078 -> 891 ms**. Modest, and worth recording as such: the allocations were
  not the bulk.
- ~~**61d. The lexer copied the file to look at it.**~~ **Done.** `LogicalLine` and each token
  are `Cow` now, borrowed unless a comment, quote, escape or parenthesis means
  the token is not a contiguous run of the file. **347 -> 325 ms**, against a
  measured floor of 22 ms for a bare borrowing split.
- ~~**61e. The index value is a `Vec` per owner name.**~~ **Done, `Zone::Slot`.**
  1M heap allocations of one element each, 32 bytes to hold 8.
  `enum Slot { Ent, One, Spilled }` with the single case handed out through
  `slice::from_ref`, so it has nothing on the heap and one fewer pointer to
  chase. **Lookup is not slower** — `Zone::locate` 58/62 ns hit, 65/65 miss,
  the hit path ~10% *faster*.

  **The `usize` shape shipped, not the `u32` one that measures better.** Both
  were built (§19): `u32` holds 308 B/rule against `usize`'s ~342, and buys that
  33.5 MB per million with either an `expect` in `Zone::file` — a panic on a
  load path, where this codebase wants a typed error (§4) — or a public
  signature change to make `add_record` fallible. Neither is worth 33 MB, and
  the row is left here rather than deleted because the number is real and a
  checked boundary would unlock it.
- **61f. What landed, measured together.** 61a-e were prototyped in three
  separate passes and none of them measured the combination; these numbers are
  the merged tree, taken with the same harness and against the same baseline as
  #57b's:

  | at 1M rules | before | after | |
  |---|---|---|---|
  | `PolicyZones::load` | 2.38 s | **0.633 s** | 3.76x |
  | `PolicyStore::reload` | 2.74 s | **0.952 s** | 2.88x |
  | held | 407.3 B/rule | **339.4** | -68 MB |
  | reload peak | 1061.8 B/rule | **758.8** | -303 MB |

  100k reloads in 71 ms against 170. The residual per-rule drift is the 2M-entry
  table's cache behaviour and is inherent.

  **Still open, upside measured, risk named:** keying the index by a 64-bit hash
  would take ~339 -> ~122 B/rule, but a bare hash key is an attacker-findable
  wrong answer, so it needs a witness record verified on every probe — including
  the miss path a random-subdomain flood sends — and **that cost has not been
  measured**. The one proxy attempt returned 4 ns for a random read into 50 MB,
  which is not credible.

**The 2x reload peak does not go away.** `reload` peak = old held + new load
peak, exactly. Per-zone build-then-swap buys nothing in the case that matters:
with one big feed, "old zone + new zone" *is* "old set + new set". It would only
help a set of many zones, and only by giving up the all-or-nothing property that
is the whole point (§4).

#### Parallelism and rayon: measured, declined

Recorded so it is not re-derived. `zone/parse.rs` couples every line to its
predecessors five ways — an omitted owner, `$ORIGIN`, `$TTL`, `$INCLUDE`,
parentheses — and a sixth that is not obvious: **an explicit per-record TTL
writes back to the parse state** (RFC 1035 §5.1, "Omitted class and TTL values
are default to the last explicitly stated values"), so a chunk's entry TTL
depends on every line above it. The serial state walk is irreducible.

Measured ceiling p ~ 25%, at most 49%; Amdahl at 16 cores 1.29-1.88x. Built
anyway (§19): a two-pass parser reaches **1.41x at 4 threads**, is **0.68x at
100k** — slower — and the restructuring alone costs 8% before a thread starts.
At the size most operators run, a national blocklist of thousands of names, the
whole parse is 13 ms.

**The refuting measurement, taken first because it was most likely to settle
it:** with 15 querier tasks on 16 workers, the serial reload costs the answer
path **0-4%** of query throughput — `spawn_blocking` uses the one spare core —
and a 16-thread reload costs **17-34%** and roughly triples tail latency. Under
load the parallel reload **is not faster at all**: 4.37 s against 4.29 s. The
displaced work is conserved; parallelism only concentrates it into a shorter,
deeper dip. The one case it wins is an oversubscribed box, paid for in
throughput.

Across *files* `PolicyZones::load` is a loop with no coupling and parallelises
near-linearly (9.7x over 16 equal feeds), but it is bounded by the largest file,
and the realistic shape is one huge commercial feed beside small national lists.
If it is ever wanted it is ~15 lines of `std::thread::scope` and must collect
every result and fail on the *path-order* first error, or §4's all-or-nothing
gets a nondeterministic message.

**rayon specifically: no.** Five packages, and — measured rather than read, which
is §14's rule — one `par_iter()` call leaves **16 resident OS threads** for the
life of the daemon. `std::thread::scope` matched it on every timing taken
(3.69x vs 3.67x, 9.52x vs 9.71x, 1.31x vs 1.29x) and leaves nothing behind.
There is no measurement in which rayon wins. A faster hasher was built too, and
is *worse*: reserve plus a hand-rolled Fx is 599 ms against reserve alone at
423.

---

### 62. Three unbounded-input traps behind an assumption nothing enforces — **filed and closed 2026-09-14**

Found while measuring #61, none of them the thing being looked for. The shape is
one: a loop written under a stated belief about how big its input is, with
nothing checking that the belief holds, and the input supplied by a file. For an
`--rpz` feed that file is a *third party's* — the commercial malware feeds are
exactly the large ones — so "the operator would not do that" is not the
reassurance it is elsewhere. `CLAUDE.md` §5's "count the multipliers, and time
the worst case rather than reading the loop".

- ~~**62a. A per-query linear scan for longest-prefix match.**~~ **Done.**
  The worst of the
  three, because it is on the answer path. `PolicyZone`'s `client_ip`,
  `response_ip` and `ns_ip` are sorted `Vec`s scanned end to end per query, under
  a comment that says why: *"Longest prefix wins, which a linear scan gives once
  the list is in that order. These lists are tens of entries: a feed's bulk is
  QNAME triggers."* Nothing enforces it, and an IP blocklist delivered as RPZ is
  all `rpz-ip`. Measured on the miss path, which is what every ordinary query
  pays: **131 ns at 10 rules, 3.00 us at 1 000, 32.1 us at 10 000, 204.6 us at
  50 000** — linear at ~4 ns a rule. `benches/answer_path.rs` reads 522 ns for a
  whole answer and 3.6-4.1 us for one `sendto`+`recvfrom` pair, so at 50k rules
  the policy scan is ~400x a whole answer. ~~No remedy filed: longest-prefix
  match wants a different structure, and which one has not been measured here
  (§18 — a row naming a wrong remedy is worse than one naming none).~~ **Three
  shapes were built and measured before one was kept** (§19), which is what the
  row was waiting for.

  What landed is `rpz::IpIndex`: the rules are flattened once, at index time,
  into **disjoint address spans in address order with the winning rule already
  chosen**, so a query is one binary search. Re-measured in release through
  `PolicyZone::client_action` on the same miss path, one harness, one machine —
  **scan 29 ns / 2.81 us / 28.1 us / 144.6 us** against **index 2 / 5 / 7 / 7 ns**
  at 10 / 1 000 / 10 000 / 50 000 rules. 20 000x at 50k, flat from 10k on, and
  not slower on the ten-rule feed the old comment assumed.

  **The shape the row would have named was the wrong one.** A hash map per
  prefix length, probed longest first, is the obvious answer and is what a
  guess would have filed; the measurement that could refute it (§19) is a feed
  using every prefix length, which is legal and which nothing enforces either.
  It reads 10-13 ns on a feed of host rules and 57-60 ns on five lengths, but
  **1.9-2.3 us when all 129 v6 lengths are present** — it moves the unbounded
  multiplier from the rule count to the prefix-length count rather than
  removing it. The span table is 5.7-8.8 ns on that same feed. A trie was not
  built: its bound is 32 or 128 pointer chases, and the span table is already
  under 2% of a 522 ns answer, so there is nothing left for one to win.

  Two smaller things the building decided, neither of them arguable beforehand.
  v4 is widened into the same `u128` arithmetic rather than given a `u32` table
  of its own — measured **faster** that way (9.5 ns against 14.7 at 50k) as well
  as being one code path instead of two to drift (§7). And the memory is the
  price: a span is 48 bytes against the 18 the `(IpAddr, u8)` pair took, spans
  equal the rule count for a feed of host rules and reached **1.4x** it where
  prefixes nest, so 50 000 rules cost ~1.5 MB more and ~2.9 MB more in the worst
  shape measured.

  The guard is a ratio, not a wall-clock floor (§10):
  `a_query_costs_the_same_however_many_address_rules_the_feed_holds`. Verified
  failing against the scan at exactly **10.0x** — 14.8 us at 1k against 148.2 us
  at 10k, in debug — and passing at ~1.4x. A `::/0` rule is a test of its own,
  because that span ends at `u128::MAX` and advancing past the last one would
  wrap to the bottom of the space.

  `security::prefix_matches` is private again: `rpz` shared it while its
  triggers were a list scanned per query, and turns each prefix into a range at
  load instead. **`TransferAcl` still scans and is left alone deliberately** —
  every one of its lists comes from `--allow-transfer`, `--query-rate-exempt`,
  `--rpz-notify-from` or their config equivalents, so it is bounded by what an
  operator typed, which is the enforcement #62's other two items lack.
- ~~**62b. `PolicyZone::new` de-duplicates trigger owners quadratically.**~~
  **Done.**
  `seen: Vec<Name>` probed with `seen.iter().any(...)` per record landing in a
  trigger subtree. Zero for a QNAME feed, which is why #61 measured the whole of
  `PolicyZone::new` at 41 ms and saw nothing. Measured on address triggers:
  **6.7 / 23.3 / 92.8 / 400.3 ms at 2k / 4k / 8k / 16k**, four times per
  doubling; the same feed shape reads 114 ms at 10k and 3.73 s at 50k through
  `PolicyZones::load`. A `HashSet<Name>` — `Name`'s `Hash` is the same RFC 4343
  fold the scan compared by — takes 16k to **8.5 ms**, linear, with identical
  `trigger_counts`. Independently reproduced end to end: a 50k-rule feed loads in
  **53 ms against 3.73 s**, 70x.

  The regression test is a *ratio*, not a wall-clock floor (§10): doubling the
  rules must not quadruple the work. Verified failing against the scan —
  59.5 ms at 8k against 236.8 at 16k, 4x — and passing at ~2x with the set.
- ~~**62c. A top-level `$ORIGIN` reindexes the whole zone.**~~ **Done.**
  `parse.rs` called
  `Zone::set_origin` for each one and `set_origin` calls `reindex()`, which
  rebuilds the index over every record parsed so far — O(sections x records).
  Measured at 40 000 records: **47.6 ms with one `$ORIGIN`, 104.8 with 16, 306.6
  with 64.** The worst legal shape, an `$ORIGIN` before every record, is
  ~O(n^2.2): **530 ms at 2k records, 1.90 s at 4k, 8.88 s at 8k, 41.53 s at
  16k.** Not remote-triggerable — no wire path builds a `Zone` through the text
  parser, since AXFR assembles records directly — but it is a startup or reload
  hang with nothing alerting, from a file somebody else wrote.

  **Only the last `$ORIGIN` decides the apex, and the rebuild is a clean sweep of
  the whole zone**, so the parser now does it once: a `$ORIGIN` arriving before
  any record is taken immediately, where the rebuild is over nothing, and one
  arriving after a record is remembered and applied when the file ends. A file
  with a single `$ORIGIN` at the top — which is where one usually is — pays
  nothing at all, and every other file pays one rebuild.

  Re-measured in release, one harness, before and after. It reads lower
  throughout than the figures above, which were taken with a heavier generator,
  so the pairs are what to read and not the halves: 40 000 records
  **18.9 -> 16.9 ms with one `$ORIGIN`, 46.4 -> 19.0 with 16, 136.4 -> 18.9 with
  64**; an `$ORIGIN` before every record **167.1 ms -> 1.5 at 2k, 801.7 ms -> 3.1
  at 4k, 3.81 s -> 6.0 ms at 8k, 13.64 s -> 12.0 ms at 16k** — 1 137x, and 2.0x
  per doubling where it was ~4x.

  **The chains were the other half, and nothing had opened `chain_key`**
  (`CLAUDE.md` §4). `reindex` cleared and rebuilt `nsec_chain` and `nsec3_chain`
  under a comment saying they move with the origin. They do not: a chain key is
  the record's own owner name, absolute, and a position in `records` — both
  unchanged by an apex that moves, so the rebuild was a base32 decode per NSEC3
  and an n-element `Vec` to arrive at the map it started from. Moving the apex of
  a zone holding 20 000 NSEC records: **7.72 -> 3.80 ms**.

  The guard is a ratio, not a wall-clock floor (§10):
  `parsing_does_not_cost_more_per_record_when_every_record_moves_the_origin`,
  verified failing against the old parser at **3.18x** — 404.4 ms at 1k records
  against 1.284 s at 2k, in debug — and passing at ~2x. Beside it,
  `a_late_origin_leaves_the_zone_setting_the_apex_first_would_have` is the
  correctness half: deferring the move must leave the same zone, so it compares
  the whole index and the shortcuts against the same records added to a zone
  whose apex was right from the start — an NS RRset that is a delegation under
  one apex and the apex's own under the other, a wildcard, and a name whose
  ancestors are empty non-terminals only for an apex above them.

**Answered, where the row said it was not measured:** the only caller that needs
`set_origin` at all is the zone parser, and it now calls it once. `reindex` is
still what makes it O(records), and `set_origin`'s doc comment says so, so the
next caller is told the cost rather than finding it.

---

### 63. `rdnsr` has 39 flags and no config file — **filed 2026-09-14, closed 2026-09-15 by 63h's shape C, with 63j the per-feed policy it was for**

Filed out of 57d, which cannot be decided without it: a transfer spec is per
zone, and there is nowhere to write one. Filed as its own number rather than
left in 57d's prose because **a prerequisite named in prose is a prerequisite
nobody schedules** (§18), which is precisely what 57d's paragraph has been
doing since it was written.

**The sentence that would make this row wrong** (§19), written down first and
then checked: *"only 57d wants this, and 57d may be declined — option C is
unbeaten, so the config file buys nothing."* **It is false.** `--rpz-policy`'s
own doc comment already concedes the point, in the tree, today, with no 57d
anywhere near it: *"Applies to every `--rpz` zone: a per-zone policy wants a
config file, and this daemon has flags."* A resolver measuring a new feed in
`passthru` before enforcing it must do so to **every** feed at once — which is
the opposite of how a feed is introduced. So there are two independent demands,
and the older one is live. That doc comment is itself §18's "a sentence naming
remaining work is a `TODO.md` item, or it is deleted", found by going to look.

- **63a. Where the parser lives is the question — ~~and it is unmeasured~~
  answered 2026-09-14.**
  ~~`rdnsd/src/config.rs` is **1,402 lines and 84 `pub` items**, and it is a
  module of a *binary*, so those 84 are public only to `rdnsd`. Moving it into
  `rdns` makes all 84 genuine public API. **#37's rule is that the measurement
  for a split is visibility, not line count, and that measurement has not been
  taken** — how many of the 84 a second consumer would actually name is the
  number that decides this, and counting it is the first hour of the work.~~
  **Taken 2026-09-14. It is 18, not 84, and the file is sealed to prove it.**

  The 84 reproduce (1,411 lines now) and are **10 types, 5 functions and 69
  fields**, which is the first thing the row did not say: most of the surface
  is `serde` deserialization targets spelled `pub` out of habit, and `serde`
  does not require it.

  Counted by the compiler rather than by grep, because a field read is not a
  `config::` path and would not have shown up in one: every `pub` in the file
  was stripped, and what `rdnsd` then failed to compile without is the answer.
  **18** — 5 types (`Config`, `PerZone`, `GroupRule`, `ZoneSigningOverride`,
  `DnskeyRrsig`), 2 methods (`Config::load`, `Config::apply`) and 11 fields, on
  those last three types only. The other 66 never leave the file, including all
  34 of `Server`'s and all three of `Config`'s other spec-building methods.

  **So the split decision is about 18 items, not 84**, and the line count was
  never the measurement — #37 said so and this is the number.

  Landed with it, because the measurement is only true once the file says so:
  the 66 are private and the 18 are `pub(crate)`, which is what the rest of
  `rdnsd` already uses. **`config.rs` and `control.rs` were the only two of
  eleven modules spelling a bare `pub`** — 93 between them against 111
  `pub(crate)` everywhere else, and `control.rs` is the `cfg(unix)` file
  Windows never compiles (§1). `control.rs`'s 9 went as **63f**, which answered
  9 of 9.
- **63b. A second parser would duplicate 22 keys.** Counted, not estimated:
  `rdnsd`'s `[server]` table has **34 keys, and 22 of them are already `rdnsr`
  flags under the same name** — `host`, `port`, both rate knobs and the exempt
  list, all five anomaly thresholds, all four request/response size caps, the
  three listener addresses and `https-path`, `tls-cert`, `tls-key`,
  `metrics-listen`. That is §7's case with a number on it: two parsers for one
  setting is how `[zones."x"].also-notify` came to be parsed into a field read
  by nothing (#46c).
- **63c. What `rdnsr` has no flag for at all.** A TSIG keyring, a zone
  directory, and the three `transfer-tls-*` keys — which are, measurably, three
  of the twelve `[server]` keys `rdnsd` has and `rdnsr` does not. 57d needs all
  of them plus a per-zone spec; `MasterSpec::parse` and `rdns::endpoint` already
  parse the spec itself, so this is where to put it and not how to read it.
- **63d. Two rules this inherits already decided, so they are not open
  questions.** §15's "two sources for one setting is an error, not a precedence
  rule" — `--config` with `--port` is refused in `rdnsd` and must be in `rdnsr`.
  And §15's "`Option` per field for an override, not a whole struct": absent in
  a `[zones.*]` section means *inherit*, which is exactly what a per-zone
  `rpz-policy` needs.

- **63e. Sixteen settings had their default written twice — filed and closed
  2026-09-14**, found while taking 63a. Not the parsers, the *defaults*.
  `rdnsd/src/config.rs` had 17 `default_*` functions for `#[serde(default)]`,
  and 16 of them restated a number `rdnsd/src/main.rs` already wrote as a clap
  `default_value` literal: `host`, `port`, `response-rate`, `query-rate`,
  `query-burst`, `max-udp-request`, `max-tcp-request`, `udp-payload-size`,
  `max-udp-response`, all five anomaly thresholds, `dnstap-max-bytes` and
  `validity-days`. Nothing tied any pair and no test compared them.

  **Why it was silent rather than merely untidy.** `Config::apply` overwrites
  `cli` field by field, so the two sets are never both in force: an operator
  with a config file gets config's number and one with flags gets clap's, and
  a pair that disagreed would look correct from either side. That is §15's
  "two sources for one setting" — the rule this daemon already enforces by
  *refusing* `--config` with `--port` — applied to the default instead of to
  the value.

  **Three comments named the hazard and none of them held it.** `main.rs`'s
  `--dnstap-max-bytes` doc said the config file "is the same setting and the
  same default, which `config::default_dnstap_max_bytes` holds so the two
  cannot drift" — it held one; clap held `"1073741824"` beside it.
  `default_dnstap_max_bytes`'s own doc said the same thing from the other end,
  and a third, over the anomaly block, said "the same numbers as the flags'
  defaults, which is the only place they may disagree". §4's claim to verify,
  three times, and the test beside the first asserted the serde default against
  the function that produces it — §1's test agreeing with the code.

  **Fixed where the shape already existed.** Two settings were already right
  and both point the same way: `--udp-workers` is
  `default_value_t = default_udp_workers()` with `config` citing
  `crate::default_udp_workers`, and `https-path` is a shared const. So the 16
  functions moved to the crate root beside `default_udp_workers`, `config`
  cites them as `crate::default_*`, and every flag is `default_value_t`. A
  flag's default is the daemon's and the file inherits it; an item private in
  the crate root is visible to every module under it (§17), so this adds no
  `pub` and does not reopen 63a's sealing.

  **`--help` is byte-identical** on all 23 rendered defaults, which is the
  check that the `default_value` → `default_value_t` conversion changed
  nothing: `Display` for `f64` 50.0 is `50`, as the literal was.

  **The test is a tripwire, not a regression test** (§10): all sixteen pairs
  agreed when they were counted, so nothing here was a wrong value.
  `a_minimal_config_changes_no_flag_default` applies a minimal config to a
  default `Cli` and asserts the sixteen fields are unmoved, which catches the
  *seventeenth* setting added with a fresh literal on each side. Run against
  the shape it forbids — a `query-burst` serde default of 201 — it fails
  naming `server.query-burst`.

  The seventeenth existing one, `default_algorithm`, is not one of these: it
  spells the algorithm into the spec string `TsigKey::parse` reads, so §15's
  "reuse the parser the flags use" is working there and there is no second
  default.
- **63f. `control.rs`'s nine bare `pub`s — filed and closed 2026-09-14.** The
  rest of 63a's sweep, and the measurement came out the other way round.
  `config.rs` and `control.rs` were the only two of `rdnsd`'s eleven modules
  using a bare `pub`; the crate has none now.

  **All nine escape: 3 items and 6 fields, 9 of 9**, against `config.rs`'s 18
  of 84. Same method — strip every `pub`, let the build name the survivors —
  run on Linux, because the module is `#[cfg(unix)]` and the development
  machine does not compile it (§1), so the method would have reported
  everything as unused here.

  Nothing was `pub` by habit, and the reason is visible in the two shapes:
  `Control` is a struct `main.rs` *builds*, so every field is an argument at a
  call site outside the module, while `config.rs`'s structs are ones `serde`
  fills and 34 of `Server`'s fields are read only by `Config::apply` next door.
  "Who writes the field" is what the visibility follows, which is the thing
  neither file's bare `pub` said.

  So this is `pub` to `pub(crate)` and no sealing: no API is narrowed, and the
  value is that `pub` on a binary's module now means what it says everywhere in
  `rdnsd`.

- **63g. What `rdnsr` would name of `rdnsd`'s config: none of it — measured
  2026-09-14.** 63a counted the surface; this is the other half of #37's
  question, because a shared module is only shared if a second consumer names
  something in it.

  **0 of the 18.** Every escaping item is zones, signing or catalogs, and
  `rdnsr` serves none: `Config` is a top-level with `[signing]`, `[keys]` and
  `[zones]` in it; `Config::apply` takes `rdnsd`'s `Cli` *by type*; `PerZone`
  is zone files, NOTIFY targets, signing overrides and RFC 9432 group rules;
  `GroupRule` is catalogs; `ZoneSigningOverride` and `DnskeyRrsig` are signing.
  **So moving `config.rs` into `rdns` shares nothing** — it would make 18
  `rdnsd`-shaped items public API for one consumer. That option is dead, and
  63a's line count was never going to say so.

  **The type `rdnsr` would want a piece of is `Server`, which is not one of the
  18** — it is private, and 63a is why that is visible. It holds 34 keys of
  which 63b counted 22 as `rdnsr` flags already, so sharing it means exporting
  a type with 12 fields (`tls-cert`, `control-socket`, `dnstap`, the
  `transfer-tls-*` three, …) a resolver must ignore, or splitting it in two.
  That is the decision 63 still has to make, and it is between 63b's second
  parser and a split `[server]`, not between moving the module and not.

  **What is actually shared is one function.** `read_secret_file` and its mode
  check — §15's "a secret in a file is only better than a secret in `argv` if
  the file is private" — is the only code in `config.rs` that is about neither
  zones nor `rdnsd`, and 63c has `rdnsr` needing a TSIG keyring, which needs
  it. Everything else shared is serde attributes (`deny_unknown_fields`,
  `rename_all = "kebab-case"`) and a clap one (`conflicts_with = "config"`),
  which are not code to move.

  **Where the two daemons' defaults already stand**, since a config file for
  `rdnsr` has to pick a number for each of 63b's 22: of the 16 flag names both
  binaries default, **13 agree and 3 differ on purpose**. `--host` is
  `0.0.0.0` against `127.0.0.1` ("Defaults to localhost to avoid an open
  resolver"), and `--query-rate`/`--query-burst` are 1000/200 against 200/100,
  which `rdnsr`'s own doc explains: "200 where `rdnsd`'s is 1000: an
  authoritative server's clients are resolvers, and one resolver behind one
  address legitimately asks orders of magnitude more than one person does."
  So the 22 keys are not 22 numbers to unify — they are 19 agreements and 3
  decisions, all three already taken and written down.

  That doc comment does cite `rdnsd`'s number in prose across a crate
  boundary, which nothing checks; it is correct today and is the kind of claim
  §4 is about. Left as prose deliberately: the two numbers must be *allowed* to
  differ, so there is nothing to make unrepresentable.

  **And the sweep had a remainder, one crate out.** 63e cited
  `rdns::FLAG_DAY_UDP_SIZE` on `rdnsd`'s `--udp-payload-size` and
  `--max-udp-response`; `rdnsr` wrote `"1232"` for both, and its doc restated
  it a third time. Fixed with this row — §18's "count the instances before
  fixing one", which 63e obeyed within `rdnsd` and not across the workspace.
  The line it draws: a *protocol* constant belongs in `rdns` and both binaries
  cite it; a *policy* default like `--query-rate` does not, which is why the
  other 13 agreements are not a defect to fix.

- **63h. The shapes, built — 2026-09-15.** §19: arguing costs more than
  compiling, and what decided this was in neither argument. Three shapes, each
  compiling, clippy-clean under `--all-targets` and passing the suite. The two
  that were declined are kept as branches — `wip/63-shape-a` (929f544,
  76f69b7) and `wip/63-shape-b` (1d6e0e5); C's branch is deleted, because it is
  in main (c8ac8eb, b7c62a3, 1e511d0).

  The same feature in all three, so only the shape differs: `rdnsr --config`
  with `[server]`, `[resolver]` and `[rpz]`, `deny_unknown_fields` throughout,
  `conflicts_with = "config"` on all 37 file-settable flags (§15), and 63e's
  shape applied to this daemon first — 19 flag defaults moved to crate-root
  functions and every flag `default_value_t`, so the file inherits the flag's
  number. `rdnsr --help` is byte-identical but for the `--config` entry, which
  is the check that the conversion changed nothing. Per-feed RPZ policy, the
  thing #63 exists to unblock, is in none of them: it is a `[[rpz]]`
  array-of-tables away once the parser has a home.

  | | A: second parser | B: shared struct in `rdns` | C: shared fields, by macro |
  |---|---|---|---|
  | diff against main | 4 files, +633/−38 | 8 files, +799/−152 | 7 files, +789/−168 |
  | `rdnsd` | untouched | `config.rs` +135/−114, 2 tests rewritten | `config.rs` +60/−130, no test edited |
  | new public API in `rdns` | none | 24 items | 1 macro |
  | `rdns` packages | 52 | **55** (`serde`, `serde_core`, `serde_derive`) | 52 |
  | `rdns-transport` packages | 88 | 91 | 88 |
  | a typo in `[server]` | the key's line, expected keys listed | **the table's line, nothing listed** | the key's line, expected keys listed |
  | the 22 keys declared | twice | once | once |
  | their `Default` spelled | twice | twice | once |
  | folding them into `Cli` | 22 lines per daemon | 22 lines per daemon | 22 lines per daemon |
  | `cargo fmt` reaches them | yes | yes | **no — inside a macro invocation** |
  | tests, Windows / Linux | 1179 / 1199 | 1180 / not run | 1180 / 1200 |

  **What building them settled, none of which the row's prose had.**

  - **`#[serde(flatten)]` and `deny_unknown_fields` do coexist** — the *inner*
    struct's denial catches what the outer did not claim, so B's typo check
    works. What it costs is the message: serde buffers a flattened map, so a
    typo *or a wrong type* anywhere in `[server]` is reported at the table's
    line with no expected-key list, against the key's exact span today. That is
    §15's "must fail at startup with a line number", and B regresses it for
    `rdnsd`'s existing file, not only for the new one.
  - **Sharing a declaration does not share its application.** All three fold 22
    keys into a `Cli` with 22 lines per daemon. The alternative was built and
    thrown away: a `ServerCommon::apply_to` taking 22 `&mut` arguments, three
    `Option<String>` listeners among them, where transposing two compiles (§14).
  - **B's `Option` per key is forced, not chosen**: `host`, `query-rate` and
    `query-burst` differ per daemon on purpose (63g), so a shared *struct* can
    hold no default and every key becomes an override. C keeps the values,
    because the defaults come from the calling crate's root by name.
  - **A derived `Default` beside `#[serde(default = "…")]` silently disagrees
    with it.** In B an absent `[server]` meant `max-inflight-udp = 0`, which
    `check` refuses; the tripwire test caught it. Same class as 63e, one level
    down: two spellings of one default with nothing comparing them.
  - **`rdnsc` and `rdnsctl` are not affected by anything here** — both depend on
    `rdns-core`, not on `rdns`, so B's three packages stop at `rdns-transport`
    and the two daemons. The `Cargo.lock` is unchanged in all three shapes:
    `rdnsd` already paid for `toml` and `serde`, and `rdnsr`'s own tree goes
    104 → 113 either way.

  **The measurement that could have refuted the recommendation** (§19), taken
  before making it: *"the 22 keys never actually move together, so declaring
  them twice costs nothing."* **False.** Of the 23 commits that have touched
  `rdnsd/src/config.rs`, **12 also touch `rdnsr/src/main.rs`**, and 7 of those
  12 are this exact class — the UDP reply cap, the anomaly thresholds, the
  request-size caps, UDP admission, and DoT, DoQ and DoH, each adding one
  setting to both daemons in one commit. So the duplication does recur, about
  seven times over the project's life, at three lines a time in a commit that
  already edits both crates.

  **And one that refuted a cost.** A's real risk is not those three lines, it is
  #46c's shape — a key and a flag that mean one setting with nothing comparing
  them. clap can compare them: `get_arg_conflicts_with` names every flag
  `--config` replaces, and that set *is* what the file must be able to say.
  `every_flag_the_file_replaces_has_a_key_in_it` (76f69b7) walks it, watched
  failing against a deleted `resolver.prefetch`. It is shape-independent, so it
  is not a point for A over B or C — but it means A's duplication is checked
  rather than trusted.

  **C landed, and B is out.** B's one advantage — the 22 keys declared
  once — is C's too, and C also shares the `Default` the other two spell twice,
  while B pays for it with the error message operators read at 3am, three
  packages into a library that reads no files, and 24 public items for one
  consumer. C's cost is narrower and visible: the declarations sit inside a
  macro invocation, so `cargo fmt` stops reaching them (§12), `grep` for a key
  lands in `rdns/src/config.rs` rather than the daemon's own file, and the
  contract "the calling crate's root defines these `default_*` functions" is
  prose enforced by a compile error. `clippy::crate_in_macro_def` fires on
  precisely that contract and is allowed with the reason beside it. A was the fallback and
  loses only the single declaration — nothing an operator can see.

  **What landed**: c8ac8eb (the file), b7c62a3 (the flag-to-key tie) and
  1e511d0 (`rdns::server_table!`), against 1181 tests on Windows. What is left
  of #63 is 63j.

- **63i. One `[server]` key's flag was not refused beside `--config` — filed
  and closed 2026-09-15**, found while counting what a config file for `rdnsr`
  has to do. §15's "two sources for one setting is an error, not a precedence
  rule": `rdnsd --config x.toml --dnstap-max-bytes 5` was accepted, the file's
  value won, and both numbers are valid so nothing could look wrong. 34 of the
  35 `[server]` and `[signing]` keys had the conflict; `dnstap-max-bytes` did
  not, under a doc comment saying the file "is the same setting" — §4's claim
  to verify, beside the pair 63e had already corrected for the *default*.

  **1 of 35, counted before fixing** (§18) and counted mechanically, because a
  list somebody maintains is how this one was missed: clap knows which flags
  `--config` does not replace, and the file must then have no key for them.
  `a_setting_the_file_can_write_is_refused_beside_config` walks that set and
  parses a config naming each; watched failing, it names
  `server.dnstap-max-bytes` and nothing else.

- **63j. Per-feed RPZ policy, which is what #63 was for — filed 2026-09-14,
  closed 2026-09-15.** The shape the row named is what landed, one level deeper
  in the file: `[[rpz.feeds]]` and not `[[rpz]]`, since `[rpz]` still holds the
  two settings that are about the set — `policy`, now the default a feed
  inherits, and `notify-from`. An array of tables because the order of the feeds
  is the order they are consulted; `file` required and `policy` an `Option` that
  means inherit (§15).

  **The measurement the row asked for first was a `grep`, not a benchmark**, and
  taking it is what made the row small. The per-feed override costs the match
  path **nothing, by construction**: `PolicyZone` has held its own
  `PolicyOverride` since 45a and `action_at` has always applied *that* one, so
  the diff touches `PolicyZones::load`, `PolicyStore` and a new `Feed` type, and
  no function a query calls. The refuting question (§19) — *does the query path
  read one policy for the set?* — is answered by where `PolicyStore::policy` was
  read: `reload`, and nowhere else. It is gone; the store carries the feeds.

  **`files = [...]` is deleted rather than kept beside the array**, because two
  ways to name a feed is §15's two sources for one setting. That costs the terse
  spelling for the common case, and the way to have had both was measured rather
  than argued: an `#[serde(untagged)]` entry accepting a string *or* a table
  reports a typo'd key as **"data did not match any variant of untagged enum
  FeedSpec"**, spanning the whole array, with no expected-key list — the same
  error-message regression that decided 63h against shape B, and for the same
  reason. A wrong *type* reads identically. Declined.

  **`rdnsr --check-config` landed with it**, and it is not `requires = "config"`
  where `rdnsd`'s is: every feed, anchor, ACL, prefix and certificate it checks
  is flag-settable too, so requiring the file would refuse the dry run to the
  deployments that have least else to catch a mistake. It reports how many feeds
  are *not* taken at their word, because a feed at `passthru` or `disabled`
  blocks nothing and looks exactly like a working server.

  **Two things moving it up found** (§4's "a comment records why", checked
  against what the code does). `--tls-cert`/`--tls-key` were read *below* three
  binds under a comment saying "read before anything binds, like the metrics
  listener above", and `--query-rate-exempt` was parsed below them too; both are
  above now, which is what made them reachable from the dry run. And the dry run
  does not write the `--auto-trust-anchor` file when it is absent: a check that
  creates it leaves it owned by whoever ran the check.

  Verified as a process and not by reading the diff (§4): a feed that will not
  parse and a misspelled per-feed policy each exit 1 naming the file, the flag
  form and the file form each exit 0, and `--host 192.0.2.1 --check-config`
  exits 0 where the same arguments without it die at the bind with
  `os error 10049` — which is the proof it binds nothing. Three tests watched
  failing against the one-policy-for-the-set shape:
  `each_feed_keeps_the_policy_it_was_loaded_with`,
  `a_feed_carries_its_own_policy_and_the_others_keep_theirs` and
  `a_feed_that_says_nothing_inherits_the_global_policy`. 1186 tests on Windows
  and 1206 on Linux, clippy clean on both.

**The dependency objection is already answered, measured rather than argued**
(§15's "pay for a parser; do not pay for a stub"). `toml` + `serde` is **nine
packages** — `serde`, `serde_core`, `serde_derive`, `serde_spanned`, `toml`,
`toml_datetime`, `toml_parser`, `toml_writer`, `winnow` — and `rdnsd` already
pays for every one of them, so a config file for `rdnsr` adds **0 packages to
`Cargo.lock`** and takes `rdnsr`'s own tree from **104 to 113**.

**What it unblocks, and what it does not.** 57d becomes an ordinary decision
once this exists, and #57d's option C stays unbeaten until somebody shows it is
not — this row does not decide that and must not be read as doing so. What it
does decide is that the *reason* 57d cannot be taken is not a fact about
transfers.

---

### 64. One dynamic UPDATE is five O(zone) passes — **filed 2026-09-14, closed 2026-09-16, 64g with it**

Filed with the measurement that **refuted the reason it was going to be filed**.
The finding on the way in was "the UPDATE path re-reads the zone file, so an
update is O(zone)", with the fix named as skipping the re-read. The re-read is
25% of it. §19, working as advertised.

`cargo test -p rdnsd --release update_cost -- --ignored --nocapture`, which is
`dispatch::tests::update_cost_against_zone_size`, `#[ignore]`d and refused in
debug. One record added to a zone of N, unsigned, on the development machine:

| records | total | re-read | apply | to_string | write | clone |
|---|---|---|---|---|---|---|
| 10 000 | 20.6 ms | 13.9 | 1.8 | 5.9 | 6.0 | 0.76 |
| 100 000 | 159.2 ms | 41.2 | 19.8 | 61.2 | 46.8 | 9.2 |
| **1 000 000** | **1.8 s** | **451** | **380** | **621** | **136** | **159** |

Linear, ~1.8 µs a record, and **five separate O(zone) steps for a one-record
change**. The largest is `zone_to_string` at 35%, not the re-read at 25%.

**And it is not one client's latency.** `UpdateHandling::applying` is a
`tokio::Mutex` held across the whole read-modify-write, and its doc says why:
"One lock for all zones rather than one per zone: two concurrent UPDATEs is not
a workload this has." So 1.8 s is the *server's* update throughput at that
size, for every zone at once — about one every two seconds. **On a signed zone
it is one every twelve** (64d).

- **64a. A clone nothing reads. — fixed 2026-09-14.** With no signing
  configured `apply_update_to_file` returned `applied.zone.clone()`, and the
  original died inside the `Applied` it also returns — whose `zone` field no
  caller touches, checked: `answer_update` reads only `changed` and `ignored`.
  **159 ms at 1M records, 9%**, for a copy that is dropped unread. The only
  item here that is pure waste rather than a design consequence, and the only
  one with no decision attached.

  Fixed in the type rather than at the call site (`CLAUDE.md` §17): the
  function now returns `UpdateReport`, which is `changed` and `ignored` and no
  zone, so the zone `update::apply` produced is *moved* into the installed copy
  and there is no second one to clone. The benchmark's `clone` column is gone
  because the type no longer admits the column.

  **Three instances, not one** (§18), all found by counting the shape before
  fixing the one the row named. `ZoneSigning::sign_one_incrementally` returned
  `zone.clone()` for a zone with no key — the same copy, on the *signed* path,
  for any zone the keyring does not cover; it takes the zone by value now. And
  `answer_update` took `previous` as `matching(..).cloned()`, a whole-zone copy
  of the served version that only the signer reads: `ZoneMap` holds
  `Arc<Zone>`, and `ZoneMap::snapshot` already existed for "a caller that
  cannot finish under the lock", so that one is a refcount. **The conditional
  clone written before that grep was the wrong fix** — an `Option<Option<Zone>>`
  and a `(signer, previous)` pair to make "cloned for nobody" unrepresentable,
  all of it unnecessary because the copy need never have been one. §19, and the
  refuting evidence was the declaration of the map.

  **The measurement that could have refuted it.** A single run does not show
  this: the total at 1M records read "1.8s" either way, because `{:.1?}` past a
  second is coarser than the spread of the columns it sums. The benchmark
  prints the total in milliseconds now, and putting the `clone()` back
  separates the two without overlap — **1907–1947 ms against 1694–1731**, six
  warm runs against five, on the development machine, Windows. The first run
  after a rebuild is cold and must be discarded: one read 1983.9 ms, 270 ms
  above the five that followed it, and it was *inside* the unfixed band. The
  four remaining steps are unmoved. **Four O(zone) passes now, not five**; the
  section heading is the shape at filing and is left as the identifier it is.
- **64b. The re-read, which is a policy wearing a cost — landed 2026-09-15.**
  `parse_zone_file_at` per update, under "so an edit since the last load is not
  silently reverted" — **451 ms, 25%**. The rule is defensible; paying it
  unconditionally is the part that is not. ~~Whether an mtime check is enough
  depends on a question nobody has asked: what an operator editing a file under
  a server taking dynamic updates is entitled to.~~ Both halves of that are
  answered below — the question was worth asking and the mtime framing was the
  wrong one.

  Read the bytes always; parse them only when they are not the bytes this
  server last wrote. **38% off an unsigned update at a million records.** The
  reload half of this row is now #64f.

  **The question this row said nobody had asked is answered, by measurement
  rather than by judgement.** "Whether an mtime check is enough" turns out not
  to matter: reading and hashing the file is **7.8 ms against a 435 ms parse**
  at a million records — 1.8% of what it replaces — so the honest test is
  affordable and the `stat` shortcut buys nothing. `stat` is 0.07 ms and cannot
  see an edit that preserves length and timestamp, and a missed edit is the
  operator's change silently reverted, which is the failure the re-read exists
  to prevent (§4). There is no mtime path on purpose.

  What the operator is entitled to, stated so the next person can disagree with
  it: **any change to the file, by anyone, is seen before the next update is
  applied.** Not "an edit the server can tell was deliberate", not "an edit
  since the last reload" — any difference from the bytes this server last
  wrote. That is what the digest tests, and it is strictly stronger than what
  mtime could promise.

  **The shape.** The digest lives under `UpdateHandling::applying`, the lock
  that already serializes the read-modify-write, so "this is what we wrote" is
  guarded by the lock that made it true rather than remembered beside it.
  Reuse is confined to the *unsigned* case: a signed server serves RRSIGs and
  NSECs the file does not carry, and 64d measured those four steps at 12% of a
  signed update anyway, so the case worth having is the one where the served
  copy *is* what the file holds. A signed server pays the re-read exactly as
  before.

  | records | cold | warm | saved |
  |---|---|---|---|
  | 10 000 | 21.4 ms | 15.7 ms | 27% |
  | 100 000 | 164.1 ms | 104.5 ms | **36%** |
  | 1 000 000 | 1 906 ms | 1 178 ms | **38%** |

  Three runs on the development machine, Windows, release; the spread is
  26-28%, 33-36%, 37-38%. `warm_update_cost_against_cold`.

  **Both columns moved when 64c made the writer cheaper**, and the share went
  *up* because what the warm path still pays shrank: 1 397 ms cold against
  753 ms warm at a million records, **46%**. The table above is the measurement
  as it stood and is left as it was taken.

  ~~**Built 2026-09-15 on branch `64b-digest`, and its headline number did not
  reproduce.** The mechanism is correct, tested and cheap; the 25% this row
  promised at a million records is 1-5%, and part of the gap is unexplained.~~
  ~~The saving *shrinks* with zone size, and the absolute saving at a million
  (14-78 ms) is smaller than at a hundred thousand (45 ms). That cannot be true
  if the only difference is skipping a 450 ms parse, so something else in the
  warm path grows with the zone.~~ ~~`zone_to_string` is **937 ms fresh against
  1 007 ms served** at a million records, and 63.7 against 78.6 at a hundred
  thousand. That is ~70 ms of a ~380 ms gap.~~ **Every number in that paragraph
  is a measurement of the benchmark rather than of the code — corrected
  2026-09-15**, and the reasoning is left standing because the way those
  numbers were taken is the finding. Nothing in the warm path grows with the
  zone; the saving grows, as skipping a parse must. `zone_to_string` is 645 ms
  on a fresh zone and 645 on a served one, indistinguishable, and the
  937/1 007 pair is what the same test prints while something else is running.

  **What was running was this file's other benchmark.** The recipe is
  `cargo test -p rdnsd --release update_cost -- --ignored --nocapture`, and
  `update_cost` is a *substring*: it selects `update_cost_against_zone_size`
  and `signed_update_cost_against_zone_size` both, which libtest then runs in
  parallel. So a million-record update was timed against a million-record
  signing run — 12 s of one overlapping 2 s of the other, and which call in the
  pair catches the overlap is scheduling luck. Run verbatim today it costs the
  warm call ~300 ms and leaves 22% where serialized it reads 38%; and one warm
  iteration in six spiked `zone_to_string` to 1 211 ms at a hundred thousand
  records against 62 for its neighbours, which is the size of outlier the
  recorded numbers need. **The fix is a lock rather than a better recipe**
  (`CLAUDE.md` §17): `dispatch::tests::ONE_AT_A_TIME`, held for the whole body
  of each of the three benchmarks, so the documented recipe is right whatever
  it selects and whatever `--test-threads` says. It is the only instance —
  `zone_signer`'s three `#[ignore]`d benchmarks have distinct names and no
  recipe selects two of them, and `rdns/tests/scale.rs` has one.

  **And the comparison itself was two calls that differed in more than the
  thing under test** (§1). The cold call was timed in position 1 and the warm
  one in position 2, in a process whose heap had just grown by a million-record
  zone. That is worth ~130 ms on its own, in the direction that *flatters* the
  digest, so it was not the bug — but it is why the replacement harness
  alternates cold and warm from identical state: the file holds exactly what
  the served zone serializes to, the digest is the digest of those bytes, an
  assertion checks that every round, and the only difference between iterations
  is whether `known` is supplied.

  **The decomposition, from timers inside `apply_update_to_file`** — the clean
  reading this row asked for, and its columns sum to the total within 2 ms at a
  million records, which a separately-timed decomposition cannot be made to do.
  Cold: parse 527, `update::apply` 364, freeing the parsed zone 146,
  `zone_to_string` 636, write 140. Warm: the same, less the parse and the
  freeing, plus 17 for the read and the digest. **Freeing what the parse built
  is a fifth of the saving and nothing had counted it**: a million records is
  two million small allocations to return.

  **Both hypotheses this row named are refuted, each by one measurement.**
  ~~The served zone's *index* is shaped differently from a parsed one~~ — no:
  `update::apply` costs 364 ms on a served zone against 389 on a freshly parsed
  one, and `zone_to_string` 645 against 645, inside the noise either way.
  ~~Holding the served zone alive across the warm call doubles live memory~~ —
  no: two *extra* million-record zones held live for the whole run leave the
  warm call at 1 141-1 166 ms, unchanged.

  **What has been ruled out.** The fast path *is* taken: instrumented, and the
  digest matches on the warm run at every size. The warm update changes a
  *different* record than the cold one, so it is not timing an early exit —
  the first version of this measurement did exactly that and read as a 3.3x
  win, which is §1 in its own measurement.

  ```sh
  cargo test -p rdnsd --release warm_update_cost -- --ignored --nocapture
  ```

  **The half that was never in doubt** is the safety property, and it has a
  test: `an_edit_under_a_running_server_is_seen_even_when_the_re_read_is_skipped`
  drives three updates — no digest, matching digest, matching digest after the
  file has been edited underneath — and fails against reusing the served copy
  unconditionally. Whatever happens to the performance argument, that is the
  rule the re-read was there for and it still holds.
- **64c. The file is the authority, and that is the other 42% — filed
  2026-09-14, closed 2026-09-16 with the design half declined.** The row asked
  whether the file should stop being the authority. The measurement that could
  refute it went first (§19) and did: **more than half of the 42% was not the
  file at all, it was the serializer**, and `to_string` fell **636 ms to 250**
  at a million records with the file exactly as authoritative as before.

  `rdata_to_string` built RFC 3597 §5's `\# <len> <hex>` form for **every**
  record and threw it away whenever the type-specific spelling worked — which
  is the ordinary case — and built it with a `format!` **per RDATA octet**. Four
  discarded allocations for an A record, ~110 for an RRSIG. Lazy now, and the
  hex goes through `write!` into a pre-sized buffer.
  `zone_to_string` then allocated a `String` per record and copied it into the
  output, and grew that output from empty: `record_line_into` is the primitive
  and `record_line` the allocating wrapper, which is `CLAUDE.md` §13's own
  shape.

  | at 1 000 000, unsigned | before | after |
  |---|---|---|
  | one update, cold | 1 716 ms | **1 333-1 337** |
  | `to_string` | 636 ms | **250-257** |
  | one update, warm (#64b) | 1 178 ms | **753** |
  | 64b's saving | 38% | **46%** |
  | rendering one A record | 14 allocations | **7** |

  Output byte-identical, and checked rather than assumed: the six `round_trip`
  fixtures — ordinary records, the DNSSEC types, TXT sequences, CDS/CDNSKEY and
  SOA ordering — hash to the same digests either side.

  **And the design question is declined on what is left.** `to_string` plus
  `write` is now **387 ms of a 1 335 ms cold update and 4% of a signed one**,
  against the 776 ms of 1 178 the row priced. What the remedy costs has not
  moved: four deliberate properties of the journal and a recovery path that does
  not exist, all of it buying latency rather than durability
  (`persist::write_atomically` already means no zone file is ever half-written).
  Declined here so the next reader finds the numbers rather than the question
  — if it is taken up it gets its own number.

  ~~`to_string` plus `write` — 621 + 136 ms — exist because the update must
  reach the file:~~
  `UpdateHandling`'s doc says the re-signing timer reloads every zone from its
  file, so an in-memory-only edit is discarded within one re-signing interval
  with nothing logged. **Making the file a checkpoint rather than the authority
  removes 64b and 64c together: 1 228 ms of 1 800, 68%.** It is also much the
  largest of these, and the invoice is in the next paragraph rather than in a
  remedy this row names.

  **64b landed separately, so that pairing is now only how it was priced.** An
  unsigned update does not re-read, and `to_string` plus `write` are **776 ms
  of the 1 178 ms that remains, 66%** — a larger share of a smaller number. A
  signed update is unchanged: 64b's reuse does not apply there.
- **64d. The signed path, measured — 2026-09-14. Signing is 88% of it, so
  64b and 64c are worth 10%.** ~~These numbers are an unsigned zone.
  `sign_one_incrementally` is not in them. #44c's 28 s is a *full* sign of a
  million-record zone and is an upper bound that does not apply. Whether
  signing swamps all five steps is the measurement that decides whether any of
  this matters for a signed deployment, and it wants signing keys on disk,
  which is why it is a row and not a footnote.~~ It wanted *generated* keys on
  disk, which `SigningKey::write_to_dir` supplies in six lines — the cost that
  made it a row rather than a footnote was not there.

  `cargo test -p rdnsd --release signed_update_cost -- --ignored --nocapture`,
  which is `dispatch::tests::signed_update_cost_against_zone_size`. NSEC, one
  ECDSA P-256 KSK and one ZSK; three warm runs, discarding the first after a
  rebuild:

  | records | unsigned | signed | incr-sign | full-sign | carried |
  |---|---|---|---|---|---|
  | 10 000 | 20.7 ms | 87.0 | 55.8 | 245.7 | 20004/20008 |
  | 100 000 | 165.5 ms | 931.4 | 783.7 | 2 556.1 | 200004/200008 |
  | **1 000 000** | **1 952 ms** | **11 801** | **10 315** | **26 939** | 2000004/2000008 |

  So a signed update to a million-record zone is **11.7 s, of which signing is
  10.3 s — 88%**. The four O(zone) steps the table at the top of this section
  measures are the remaining 12%, and removing 64b and 64c together — 68% of
  those — is **10% of a signed update**. The percentages in 64b and 64c are
  shares of an unsigned one and are not wrong; what changes is what they are
  worth buying.

  `full-sign` reproduces #44c's 28 s (26.9–27.3 s) by a different route, which
  is the one number here that was already known and the reason to trust the
  rest.

  **The measurement that could have refuted it** (§19) was `carried`, and it
  refuted the explanation rather than the finding. The obvious reading of
  "signing is 88%" is that a signed update pays for signatures. It does not:
  **exactly four RRSIGs are made fresh at every size** — the A RRset added, the
  two NSECs the insertion moves, and the bumped SOA — and every other one is
  carried forward byte-identical. Ten seconds for four ECDSA operations. That
  is #64e, and it is a different finding from the one this row was filed to
  take.
- **64e. Carrying every signature forward still costs O(zone), and that is now
  the whole bill — filed 2026-09-14.** Out of 64d. `sign_zone_incrementally`
  re-makes 4 signatures out of 2 000 008 and takes **10.3 s at a million
  records**, against 26.9 s for a full sign. The 16.6 s difference is the ECDSA
  the carry-forward saves; the 10.3 s that remains is `PreviousSignatures::of`
  over the served zone, `carry_over_records`, `Layout::of` and a full NSEC
  chain, ~~four O(zone) passes with no crypto in them~~ — **six**, measured
  below the same day. What the four have in common and the two missing ones do
  not is that each is a loop over `zone.records()`: `sign_everything` loops
  over a `BTreeMap` it builds from the zone first, and the sixth is a
  destructor.

  **No remedy named, on purpose** (§18: a row naming a wrong remedy costs more
  than one naming none). The obvious one — rebuild only the part of the chain
  that moved — is argued against in `sign_zone_incrementally`'s own header, and
  the argument is correct: an NSEC's `next` and its bitmap make "changed names
  plus chain neighbours" a chain that validates against itself while denying a
  name that exists (RFC 4034 §4.1.2, RFC 5155 §7.1). That header also claims
  "what is saved is the signing, which is the expensive half", and 64d's table
  says it is: 16.6 s of 26.9. Both the decision and its stated reason survive
  the measurement. What the measurement adds is that the half deliberately kept
  is 88% of what a dynamic UPDATE now costs, which is a fact about the *update*
  path that nothing about the *load* path implied.

  ~~The measurement that would let somebody start: the four passes above, timed
  apart. 64d times the signing as one column because that is what its question
  needed, and splitting it is this row's first step rather than its
  conclusion.~~ **Taken 2026-09-14, and there are six passes, not four.**
  `zone_signer::tests::incremental_sign_cost_by_pass`, inside the module
  because every pass but the whole is private:

  ```sh
  cargo test -p rdns --release incremental_sign_cost -- --ignored --nocapture
  ```

  | records | incremental | previous-sigs | carry-over | layout | nsec-chain | sign-everything | free |
  |---|---|---|---|---|---|---|---|
  | 10 000 | 50.6 ms | 10.8 | 4.7 | 3.0 | 8.2 | 20.8 | 2.2 |
  | 100 000 | 735.5 ms | 150.6 | 60.6 | 37.2 | 97.6 | 313.3 | 67.8 |
  | **1 000 000** | **9 397 ms** | **1 817** | **1 105** | **513** | **1 519** | **3 628** | **1 092** |

  And `sign-everything` split again, which is the step this row named next:

  | records | build-rrsets | sign-rrsets | file-sigs |
  |---|---|---|---|
  | 10 000 | 5.6 ms | 12.9 | 2.3 |
  | 100 000 | 69.5 ms | 209.7 | 34.1 |
  | **1 000 000** | **981** | **2 222** | **425** |

  Three warm runs on the development machine, Windows, discarding the first
  after a rebuild; spread 2.3% on the total and under 2.5% on every column.
  The parts are asserted to sum within 0.8x-1.25x of the whole, so the split
  cannot drift from `sign_zone_inner` without the test saying so.

  **The two passes the row did not name are 51% of it.** `sign_everything` is
  the largest column at **39%**, and `free`, **12%**, is dropping
  `PreviousSignatures`: it dies inside `sign_zone_incrementally` after the last
  of the other timers has stopped, and it was exactly the 11% the split was
  short of the whole before it was measured. What the four named passes have in
  common and these two do not is that each of the four is a loop over
  `zone.records()`.

  **So the carry-forward index is 2.9 s of 9.4 s, 31%, to build and to free.**
  It buys 64d's 16.6 s of ECDSA, so it is still 5.6x its own price and the
  decision stands — but the row had it as one of four equals and it is a third
  of the bill. The NSEC chain that `sign_zone_incrementally`'s header defends
  building in full is 16%, which is not the term to argue about either.

  **Inside `sign_everything`, the signing loop is 61% of it and 24% of
  everything** — and it contains the four ECDSA operations. What it does two
  million times, read off the code rather than profiled: `Layout::entry`, which
  builds a canonical key and *clones* a `NameEntry` (a `BTreeSet<Rtype>`);
  `PreviousSignatures::reuse`, which folds a key, probes two `BTreeMap`s of two
  million entries and compares the RDATA both ways; and one `ZoneRecord` per
  carried signature, cloning the name and the RDATA. `file-sigs` — two million
  `Zone::add_record` calls, the index work #61 found dominating a load — is the
  *smallest* of the three at 12%.

  **One of those allocations is gone**: `reuse` built the same folded key twice,
  once per map, and now builds it once. 2 318 ms to 2 235 ms in that column,
  three runs each side, no API change. The other two are not taken here.
  `Layout::entry` returns an owned `NameEntry` because it ends in
  `unwrap_or_default()` for a name the layout does not hold — and it carries no
  doc comment, so there is no stated reason to answer, which §19 says is itself
  the finding. And the tuple key `(folded, rtype)` cannot be probed through
  `Borrow`: that wants the maps nested, `name -> rtype -> _`, so the outer one
  takes `&[u8]` — `rdns-core::name_keys`'s own argument, and a shape change
  rather than a line.

  **Two negative results, recorded rather than dropped** (`CLAUDE.md` §10):

  - `Zone::reserve` on the output buys nothing. The signed zone ends at ~4x the
    input's record count and `Zone::new` grows from empty, so #61's 320 ms of
    index rehashing looked like free money; reserving at 1x and at 4x both read
    9.4-9.5 s, inside the run-to-run spread. #61's load has an index insert as
    its per-record work, and here that insert is behind a fold, a chain key and
    an RDATA clone.
  - Splitting `sign_everything` into `rrsets_of`, `signatures_for` and the
    filing loop — which is what made the inner table possible — is free: three
    runs each side read 9 392 ms against 9 364 ms, which overlap.

  ~~**Still no remedy named** (§18).~~ **Taken 2026-09-16, and it is the two
  structures the split named and nothing else.** What the split established is
  where one would have to go: **31%** building and freeing `PreviousSignatures`
  and a further **24%** in the loop that probes it and `Layout` once per RRset.
  Three shapes, built and measured in order:

  | at 1 000 000 | total | previous-sigs | free | sign-rrsets |
  |---|---|---|---|---|
  | before | 9 204-9 246 | 1 791-1 804 | 1 168-1 210 | 2 204-2 244 |
  | A: borrow the `Layout` entry | 9 018-9 105 | | | 2 022-2 067 |
  | A+B: borrow `PreviousSignatures` | 7 815-7 937 | 1 220-1 320 | 394-428 | |
  | **A+B+C: nest its key** | **7 919-7 965** | **1 255-1 270** | **470-524** | **1 996-2 013** |

  Three runs each, and the first and last rows were taken **back to back in one
  session** because the middle two were not: an earlier reading of C was
  7 744-7 748 against a 9 279-9 367 baseline from an hour before, and comparing
  those two numbers would have credited the machine's mood to the patch. **−14%
  on an incremental sign, and −16% on a signed UPDATE** — 11 801 ms to 9 866 at
  a million records.

  - **A.** `signatures_for` iterates `Rrsets`, which is keyed by
    `canonical_sort_key` — and then called `Layout::entry`, which *derives that
    key again* and clones a `NameEntry` (a `BTreeSet<Rtype>`) to read two
    bools. Two allocations per RRset, four million on a million-record zone,
    for a key already in hand. `Layout::at` borrows. The row had this as "no
    stated reason to answer, which §19 says is itself the finding"; there was
    none, and the entry now carries one for why the *owning* spelling still
    exists (an NSEC3 owner is a name the layout does not hold).
  - **B.** `PreviousSignatures` cloned the `RecordData` of every record in the
    previous zone — two million allocations to build and two million to free,
    which is exactly the 31%. It borrows from `previous`, which outlives every
    use of it. `free` fell 58%.
  - **C.** The row named this one: "the tuple key `(folded, rtype)` cannot be
    probed through `Borrow`: that wants the maps nested, `name -> rtype -> _`,
    so the outer one takes `&[u8]`". Built, and it is right —
    `Cow<'a, [u8]>: Borrow<[u8]>`, so the probe is the folded name itself and
    costs nothing for a name already folded, which every name a previous run
    wrote is. The inner level is a `Vec` scanned linearly, because a name holds
    a handful of types.

  **Two columns moved the wrong way and neither was touched**: `layout` 503-508
  to 579-630 (+18%) and `carry-over` 1 076-1 095 to 1 132-1 150 (+5%). Recorded
  rather than explained away — removing two million live allocations before
  those passes run changes the heap they run against, and +90 ms of that is set
  against −1 290 ms net.

  **The invariant is unmoved**: `signed_update_cost` still reports
  2 000 004 of 2 000 008 signatures carried forward byte-identical, which is the
  measurement that would have caught a reuse rule broken by the key change.
  `sign an eight-record zone` fell from 922 allocations to 593 — below the
  assertion's floor, which moved to 400 with the reason beside it (§17 asks for
  one in either direction).
- **64g. `rrsets_of` clones the whole zone to sign it — filed and closed
  2026-09-16**, out
  of 64e, which left it as the one named pass it did not take. `build-rrsets`
  is **930 ms of 7 940 at a million records, 12%**: one `RecordData::clone` per
  record, into a map `signatures_for` consumes and drops. It could borrow from
  `signed` the way #64e's B made `PreviousSignatures` borrow from `previous` —
  the borrow ends before `add_record` is called, so the checker allows it.

  **No remedy claimed, because the obstacle is not in this function**:
  `Rrset::new` takes `&'a [RecordData]` and `Rrset` is the granularity the
  whole of `dnssec` works at, `verify_rrset` included. A borrowed
  `Vec<&RecordData>` does not fit it, so this is a change to a core type's
  shape and its call sites, not to a loop. Whoever takes it should count those
  first (§18).

  **Taken and closed 2026-09-16, and the obstacle it was filed with was not
  there.** The count §18 asks for went first: `Rrset::new` has **43 call
  sites** and `Rrset<'_>` appears in **three signatures** — `verify_rrset`,
  `SigningKey::sign_rrset` and a test helper — so "a change to a core type's
  shape and its call sites" is one default type parameter and **zero call
  sites**. `Rrset<'a, R = RecordData>` with `R: Borrow<RecordData>` on the
  three consumers compiled the other 40 unchanged; `signed_data` took the same
  bound.

  **What it bought, three runs each side at a million records** (Windows,
  release, `incremental_sign_cost_by_pass`):

  | column | before | after |
  |---|---|---|
  | build-rrsets | 891-944 | **689-718** |
  | sign-rrsets | 2 010-2 054 | 2 096-2 169 |
  | file-sigs | 421-427 | 461-486 |
  | **total** | **7 958-8 056** | **7 939-8 012** |

  **The named pass fell 25% and the total did not move.** The two passes that
  rose were not touched and their ranges do not overlap the old ones, so this
  is not noise: the clone was *buying locality*. It laid the RDATA out in the
  order the signing loop reads it, and a borrow leaves that loop chasing a
  pointer per record into a record vector held in insertion order. 64e saw the
  weaker version of this — "removing two million live allocations before those
  passes run changes the heap they run against" — and here it is the whole
  effect rather than 90 ms of it.

  **Kept, on the one measurement that does not depend on what else the machine
  is doing** (§10): `sign an eight-record zone` reads **593 -> 566**
  allocations, two per record gone, and at a million records that is two
  million allocations and two million frees off a pass that runs on a worker
  which is also answering queries (§9). It is landed as a wash on the clock and
  said so in `rrsets_of`'s doc comment, not as a speed-up.

  **What this also settles without building it**: the narrower shape — keep the
  map owning, but clone only the RRsets that are actually re-signed — removes
  the same clones on the incremental path and none on a full sign, so it cannot
  move a total that the wider change left where it was.

  **The 12% is therefore still on the table and it is not this function's.**
  What would move it is the same thing #71a names: `Zone` holding its records
  in an order signing can walk, rather than every pass paying to reorder what
  it reads.

  **Half of that is this row's and half is not, and #65 is the half that is
  not.** `PreviousSignatures` is built by `sign_zone_incrementally` alone,
  which reaches only the UPDATE path; the four passes around it are
  `sign_zone_inner`'s and a full sign pays them too, at the same 4.4 s. Filing
  the shared half here would schedule load-path work against an UPDATE's
  measurement.

  **#65 closed on 2026-09-14 without filing it either**, and said why: the five
  shared passes are 16% of a full sign against 48% of an incremental one, so
  splitting one piece of work across two numbers is how both get half-done. It
  is unowned on purpose and the number to beat is 4.4 s at a million records.
  Whoever takes it takes both sides.

**What 64c would actually cost, since "add a WAL" is the wrong description.**
The journal is already where a write-ahead log sits — `zones.rs` writes it
before installing, under one guard, and `persist::write_atomically_str` fsyncs
it. Four properties stop it being one, each of them a deliberate decision with
a comment on it: it is **regenerated whole on every change** ("safe to delete"),
so a commit is O(history) and not O(change); it is **bounded at
`MAX_DELTAS_PER_ZONE = 32` and drops the oldest**, where a log may be truncated
at a checkpoint and not one record sooner; it is **explicitly best-effort** ("a
journal that will not read is not fatal"), where a log's failed write is a
failed commit; and its contents are **RFC 1995 difference sequences chosen for
secondaries**, not a redo record. All four would have to change, and there is
no recovery path at all today.

**And the narrowing that keeps this honest:** `persist::write_atomically` means
the zone file is never half-written, so unlike a database there is no torn-write
problem here to solve. 64c buys latency, not durability. Pricing it as
durability work is how it would get over-built.

- **64f. The reload path wants the same did-the-file-change test — filed
  2026-09-15, closed 2026-09-16.** **11 400 ms to 39 ms** for an unchanged
  million-record signed zone, measured on the same harness either side
  (`reload_cost_against_zone_size`). Out of 64b, which is where it sat as 65c's
  option C (moved there 2026-09-14). With #65a landed a reload signs each zone against the
  version being served, which is 9.7 s at a million records instead of 27.6; a
  zone whose file did not move needs neither, and could keep the served
  `Arc<Zone>` untouched. That is worth 9.7 s per unchanged zone on every
  SIGHUP, so a hundred-zone server where one file moved pays ninety-nine of
  them today.

  ~~Nothing more is needed than the did-the-file-change test above, which is
  why the two are one row: taking either answers both.~~ **Taking 64b did not
  answer it, so it is its own row** (§18). 64b's digest is a `HashMap` under
  `UpdateHandling::applying` — a lock the update path holds and the reload path
  does not, and a map keyed by the paths *updates* have written, which on a
  server taking no updates is empty. What the two share is the argument, not
  the mechanism: the bytes are cheap to read and hash (1.8% of the parse at a
  million records), and the operator is entitled to have any edit seen.

  ~~What it would cost is not yet measured~~ — **taken first, and it is larger
  than the row's estimate**: a reload of an unchanged directory is 11.4 s per
  million-record signed zone, not the 9.7 s the row carried over from 65b,
  which was the signing alone. `first` in the same table is 27.9 s, so an
  unchanged reload was 41% of a cold one.

  | records | first load | unchanged reload | after |
  |---|---|---|---|
  | 10 000 | 904 ms | 61.7 ms | **0.55 ms** |
  | 100 000 | 2.7 s | 850 ms | **4.2 ms** |
  | **1 000 000** | **29.1 s** | **11.4 s** | **39 ms** |

  What is left at a million records is the directory scan, the read and the
  digest. The update path is unmoved: 1 716 ms total against the 1 713-1 731
  band #64a recorded.

  **The 39 ms is 15.6 ms since 2026-09-16**, and the table is left as it was
  measured. The `$INCLUDE` test this row introduced uppercased every line of
  every file, which is an allocation per record; #71b found it on moving the
  code into `rdns` for a third caller and replaced it with
  `eq_ignore_ascii_case`. Nothing about what the condition *decides* moved.

  **The two conditions, and neither is about the output.** The file's bytes are
  what this process last parsed, *and* the signing this reload would do has the
  same key roles as the signing whose output was verified. The second is
  `ProvenSigning`'s existing comparison, which is not a coincidence and is the
  thing that makes this small: **a reload that may skip the verification
  because nothing about the signing moved is a reload that may skip the
  signing.** A key crossing its Activate (#44f) or a `SyncPublish` window (#55)
  changes the output with the file unchanged, and both already move
  `KeyRoles`. The moment is passed from the loader to `apply` rather than read
  twice, so a key crossing between the two reads cannot be a reload that
  silently declines to act on it.

  **An `$INCLUDE` is never kept**, and finding that is what the row was for: a
  digest of a zone file says nothing about a file it includes, so an edit to
  the included one would be exactly the silent revert the re-read exists to
  prevent (`CLAUDE.md` §4). The test is textual, on bytes the loader has
  already read — it cannot miss one, because an `$INCLUDE` the parser acts on is
  in the text by definition, and a false positive inside a TXT record costs one
  re-parse. **64b needs no such test and that was checked rather than assumed**:
  its map holds only digests of text `apply_update_to_file` itself wrote, and
  what it writes is one flattened zone.

  ~~The measurement that decides the shape is where the digest lives: a reload
  reads every zone file in the directory, so the map is the reloader's rather
  than the updater's, and the two want to agree or a reload will re-parse a file
  an update just wrote.~~ **The two maps are separate and it costs one
  re-parse, once.** The reloader records the digest of every file it reads, so
  an UPDATE that wrote a file makes the *next* reload parse that one zone and
  the one after that keep it. Sharing the map would need the digest out from
  under `UpdateHandling::applying` — the lock the doc comment argues holds it,
  because that is the lock under which "this is what we wrote" is *made* true —
  to buy one zone's parse on one reload. `digest_of` and the `$INCLUDE` rule
  are shared; the maps are not.

  Three regression tests, each shown failing against the behaviour it replaces
  (§1): an unchanged file is kept and an edited one is not (`Arc::ptr_eq`, not
  a clock), a zone with an `$INCLUDE` is never kept, and a key that activates
  stops the zone being kept.

**Not filed: a database, or a binary zone format.** #61's ablation settles it on
this tree's own numbers — at 1M records, parsing text was ~25% of a load and
building the index ~73%. A format that hands back records still to be indexed
buys the 25%. The post-#61 breakdown has not been taken, so that share today is
unknown, and taking it is the thing that would reopen this.

---

### 66. `rdnsc` cannot write what it transfers — **filed and closed 2026-09-15**

Out of #57d, and out of the question that row never asked: *what does an
operator who only wants a resolver actually run?*

An RPZ feed arrives by zone transfer — `draft-vixie-dns-rpz-04` §2 requires
RPZs to "be primary or secondary zones at subscriber recursive resolvers", and
the commercial feeds ship that way — while `rdnsr` reads a file. Something has
to bridge the two, and the only bridge in this tree is `rdnsd`: an
authoritative nameserver, run as a download client for a resolver. That is a
deployment smell and the field does not share it. BIND has the subscriber
resolver *be* the secondary; Unbound's `rpz:` clause takes a `master:` and
transfers the zone itself. Only Knot Resolver is file-only with a watchdog,
which is the shape shipped here.

**`rdnsc` is already most of the way there and nobody noticed.** `read_transfer`
does AXFR correctly — RFC 5936 §2.2's SOA-to-SOA termination, the framing, the
id check on messages after the first, a refusal detected before the read
timeout. What it does with the records is `println!("{rr:?}")`: Rust's `Debug`,
which no parser reads. Two things are missing, and only one of them is cheap.

- **66a. Record-level presentation is in the wrong crate. — done 2026-09-15**,
  in two steps: `record_line` taking the four fields rather than either record
  type, then the move, which landed as `rdns-present` under #67's decision
  below. `rdnsc` can now render a record with one crate and 46 KB. `record_to_string`
  needs `codecs` and `record_types`, both already in `rdns-core`, plus
  `denial_wire`'s base32hex and type-bitmap encoders and `format_dnssec_time`.
  **None of that is crypto** — `denial_wire` holds no hash, `Nsec3Hash` is
  `dnssec_denial`'s. It sits in `rdns` because it arrived as half of "write a
  zone file", not because it needs anything there. The *zone* half —
  `zone_to_string`, `write_zone_file` — needs `Zone` and `persist` and stays.

  **The thing to check before moving anything** (§19): `record_to_string` takes
  a `ZoneRecord`, and `rdnsc` holds `ResourceRecord` off the wire. So the
  signature that moves is not the signature that exists, and a move that lands
  the wrong one is a move done twice. `persist` has no crate-internal
  dependencies at all and would follow cheaply if the atomic write is wanted
  there too.
- **66b. Writing what arrived. — done 2026-09-15**, the printer; the rename is
  not here and is named below. `rdnsc … AXFR example.com > example.com.zone`
  now produces a file this tree's parser reads, where it printed Rust's
  `{:?}` before. One package and **+48 KB** on the binary (814 080 to 862 208),
  against the 385 KB #67 measured for reaching the same function through
  `rdns`.

  **The closing SOA is not a record.** RFC 5936 §2.2 ends the stream with a
  second copy of the apex SOA, and writing it would make a zone file that
  carries its SOA twice — which `parse_zone_file` refuses, so the bug would
  have been the whole feature. `transfer_lines` is separate from the read loop
  so that is testable without a socket, and both tests were run against the
  shapes they forbid: one fails with `unsupported record type "{"` against the
  old `{:?}`, the other with two SOAs against a loop that prints every answer.

  **The caveat is in the function's own doc comment, where a reader of the code
  finds it**: no SOA probe, so every run is a full transfer; no IXFR; no
  NOTIFY, so whatever calls this is on cron's clock and not the publisher's;
  no TSIG until 66c. It does not close #57d and is not meant to.

  ~~**What is left: the rename.**~~ **Landed with 66c**, which is why it was
  left: `persist` moved to `rdns-core` for §15's mode check, and `--write PATH`
  then cost fifteen lines. `> file` truncates in place, so a resolver that
  re-reads mid-write sees half a zone; a rename is the old file or the new one.
  The transfer is held in memory when a path is given, because a rename needs
  the whole thing first — a million-record zone is ~45 MB of text
  (`rdns/tests/scale.rs`), which is a CLI's business and not a daemon's.
- **66c. TSIG, and it is the expensive one. Decided 2026-09-15: `rdnsc` gets
  it. — done 2026-09-15, and it cost more than this row said.** Without it `rdnsc` can only fetch from masters that authenticate by
  address, which is not how a keyed commercial feed is delivered — so the
  option exists in form and not in practice.

  ~~**Measured before the decision, not after:** `ring` costs 5 packages
  (`ring`, `untrusted`, `cc`, `find-msvc-tools`, `shlex`), taking `rdnsc` from
  **34 to 39**.~~ **39 was right about `ring` and wrong about the total**: with
  `rdns-tsig` and `rdns-present` it is **41**, and the figure the row did not
  take at all is the binary — **862 208 bytes to 1 259 520, +397 KB for the
  MAC**, where the whole presentation layer was +48. `rdnsc` is 814 080 bytes
  before any of #66 and 1 259 520 after: **+55%**.

  The count was never the cost, and this row said so about the wrong thing.
  `cc` is still the durable one — **`rdnsc` built with no C toolchain before
  this and does not now** — but 397 KB is what an operator actually ships.
  `rdnsctl` is untouched at 34 packages, which is the whole reason TSIG is its
  own crate rather than `rdns-core`'s.

  **What landed.** `rdns-tsig`, exactly as 67d measured it: every `crate::`
  path in the module resolved to `rdns-core`, so the move was a rename of
  paths and nothing else, and its 27 tests came with it. `persist` moved to
  `rdns-core` for §15's mode check — it has no intra-crate dependencies, and
  core already holds `socket` and `clock`, which are the same kind of shared
  infrastructure. `rdnsc` signs the request, keeps its MAC, and verifies
  **every** envelope of a transfer, refusing an unsigned one rather than
  accepting it unauthenticated — `rdns::xfr`'s rule and the same sentence (§7).

  **A defect the tests found, which is a platform trap in a new place** (§1):
  the first shape was `--tsig-file [alg:]name:path`, and **a Windows path
  carries a colon**, so `rsplit_once(':')` cut the spec in a different place on
  the two platforms. It is `--tsig-file PATH` with `--tsig-name NAME` now, and
  clap's `requires` ties them.

  **The fixture problem for the third time** (#67f): `rdns::test_records::nm`
  is `#[cfg(test)]`, so no other crate can see it, and `rdns-tsig`'s tests
  carry three lines of their own. `testutil::ScratchDir` went the other way —
  moved to `rdns-core` and made `pub`, because duplicating it is what that
  module exists to have stopped.

---

### 67. The crate split, re-measured now that a small binary takes crypto — **filed and closed 2026-09-15**

#66c is the first time anything but the two daemons links a crypto library, and
the boundary it crosses was never written down as a rule — only as a
consequence. So the question is whether the line is still in the right place,
and the answer is a measurement rather than an argument (§19).

The line as it stands, and it is defensible: `rdns-core` is the wire format —
codes, names, records, EDNS, the message — with no runtime and three
dependencies (`thiserror`, `rand`, `base64`). `rdns-transport` exists because a
TLS stack belongs at the socket layer and because its consumers are binaries
that may use `anyhow`. `rdns` is everything else.

**Measured 2026-09-15, and it moved the ordering rather than the line.**

This row was filed the same day saying ~~"`rdnsr`, `rdnsd` **118** each" and
"`rdns` (library) 109"~~, and **both were the wrong question** — kept because
the mistake is the one bare `cargo tree` makes for you: it counts
**dev**-dependencies, so those figures included `criterion` and `dhat`, which
no binary links. What a binary links is `-e normal,build`:

| | packages |
|---|---|
| `rdns-core` | **15** |
| `rdnsc`, `rdnsctl` | **34** each |
| `rdns` (library) | 51, or **55** with build deps |
| `rdnsr`, `rdnsd` | 108, or **113** with build deps |

**The two ways to give `rdnsc` what #66 needs, priced against each other:**

| | packages | `rdnsc.exe`, release |
|---|---|---|
| today | 34 | **814 080 bytes** |
| plus `ring` (66c) | **39** | not yet measurable — 66a does not exist |
| depending on `rdns` | **72** | **1 199 104 bytes** |

The last row is the one that settles something: one reachable call into
`zone_writer` costs **+38 packages and +385 KB, 47% of the binary**, because a
dependency on `rdns` is a dependency on `tokio`, `rustls` and `ring` whatever
the caller touches. So "just let `rdnsc` link `rdns`" is out, and it is out on a
number rather than on taste. Measured by adding the dependency and a call
behind an environment check — a call that is *reachable*, since the first
attempt used a private unused function and the linker dropped it, reading
identical to the byte.

**The tangle inside `rdns` is one edge, and it costs nothing.** Of 41 modules,
only 9 reach neither crypto nor a runtime — but 30-odd of the rest reach
`tokio` through exactly one hop: `rdns::error`, which owns it because
`From<tokio::time::error::Elapsed>` can only be written where the error type is
defined. The module's own header says that and cites #31, so the reason was
answered rather than rediscovered (§19). Discount that single edge and the
free set goes **9 to 14** — `denial_wire`, `dns64`, `security` and `svcb` join
it. None of this is a *cost*: it adds no package to any binary, and §14's rule
is to count what a dependency does at run time. It is a map of where a line
could go, not evidence that one should move.

**The layering the map suggests**, if a split happens at all — each layer named
by the heaviest thing it needs:

| layer | needs | modules |
|---|---|---|
| wire | — | `rdns-core` as it stands |
| zone and presentation | `sha1` | `zone`, `zone_writer`, `denial_wire`, `svcb`, `ixfr`, `transfer`, `update`, `journal`, `catalog` |
| crypto | `ring` | `dnssec*`, `tsig`, `zone_signer` |
| runtime | `tokio`, `rustls` | `resolver`, `xfr`, `xot`, `secondary`, `notify`, `endpoint`, `shutdown`, `logging`, `tls_identity` |

`rdnsc` under #66 wants the second layer and one module of the third, and none
of the fourth.

~~The `sha1` in the second layer is `dnssec_denial::Nsec3Hash` reached through
`zone` — so a presentation split that avoids `Zone` (66a's own open question)
may not need it at all.~~ **Half right, and the wrong half is the interesting
one.** The `sha1` is indeed that one import, but `Nsec3Hash` does no hashing at
all, so the presentation split does not have to avoid `Zone` — see **67a**,
which deletes that column. **67c** does the same to the fourth layer's first
three entries. The table is the map as it was drawn before the sweep; read it
with 67a-c beside it.

**What would refute the whole thing, and why this row is now blocked.** The
only size figure here is for linking *all* of `rdns`, which is an upper bound.
Nobody has measured what `rdnsc` pays for the items it actually needs —
record presentation plus TSIG — and if that is 50 KB then a new crate buys a
manifest that reads better and nothing else, which is exactly what this row
warns against. That measurement needs 66a to exist. **So 66a goes first and
#67 finishes after it**, which is the reverse of the order this row was filed
in.

What #66 does to that is 34 → 39 for `rdnsc` and a C compiler in its build.
What it does to the *principle* is less clear, and that is this row:
`rdns-core` has been "what a tool can link without paying for a server", and
after #66c one tool pays for crypto anyway.

**What to measure, per candidate, before proposing any move:**

- what each binary links and which item made it link that;
- for each item proposed to move, its transitive dependencies *inside* this
  workspace — the measurement that refutes a move is finding the item already
  needs something core does not have (66a passes this; TSIG does not, since
  `ring::hmac` is the whole point of it);
- what a move costs the crate it leaves, since `rdns` re-exports and every path
  that changes is a `use` somewhere.

**Why each module depends on what it depends on — swept 2026-09-15, three
passes, one per layer.** The question the row was filed with was *where should
the line go*. The sweep answers a better one: **almost every heavy edge in this
crate is incidental, and four small moves undo them.** Counting the free set as
this row does above — modules reaching neither crypto nor a runtime — it goes
from **9 of 41 to 21 of 41** for roughly a dozen moved lines, none of which is a
crate change. Every count below was re-checked before being written down.

- **67a. `Nsec3Hash` is not cryptography, and it is the only reason `zone`
  reaches `sha1`. — done 2026-09-15.** `dnssec_denial.rs:220` is a `[u8; 20]` newtype with
  `from_wire` and `as_bytes`, derives only, **no trait impls at all** — it
  hashes nothing. `zone.rs` uses it at 5 sites (`:30`, `:138` as a `BTreeMap`
  key, `:259`, `:398`, `:423`), and `:423` already sits beside
  `denial_wire::base32hex_decode`. Moving the type into `denial_wire` and
  re-exporting it is **one line in `zone.rs`**; the four other importers are
  unchanged.

  `denial_wire.rs:8` states the rule — "`dnssec_denial` keeps everything that
  hashes, proves or verifies" — and `Nsec3Hash` does none of the three, so this
  finishes a sweep that stopped one type short rather than contradicting it.
  **Found independently by the zone pass and the crypto pass**, which is the
  strength of evidence #61a had.

  **It refutes this row's own layering table**: the "zone and presentation"
  layer does not need `sha1`, and a presentation split does not have to avoid
  `Zone` after all. All nine of those modules become dependency-free.
- **67b. `rdns::error` sheds `tokio` for five deleted lines and two changed
  ones. — done 2026-09-15.** The hub edge measured above is two impls, and they are not equal.
  `From<Elapsed> for TransferError` (`error.rs:155`) has **no user**: `Elapsed`
  is named nowhere in the workspace outside `error.rs` itself, and all three
  `TransferResult`-returning timeout sites (`xfr.rs:609`, `:631`, `:663`) use an
  explicit `map_err` naming the master and the zone, which the impl would have
  thrown away. An unused trait impl draws no dead-code warning, which is how it
  survived. `From<Elapsed> for ResolveError` (`:149`) is live at five sites, all
  in `resolver/recurse.rs`.

  So: delete the dead one, and move `ResolveError`, `ResolveResult` and
  `extended_error` into `resolver`, where the timeout is — **two `use` lines**
  (`resolver.rs:12`, `rdnsr/src/answer.rs:18`), since `recurse.rs` and
  `validate.rs` reach them through `use super::*`. **`rdns::error` must not
  re-export them**: a `pub use` restores the edge being cut and adds a reverse
  one. `TransferError` stays where it is — its four users straddle the
  presentation and runtime layers (`ixfr.rs:11`, `transfer.rs:9` against
  `xfr.rs:8`, `xot.rs:70`), so moving it would push `tokio` *into* the
  presentation layer.
- **67c. `XotName` is a name, not a TLS stack. — done 2026-09-15.** `endpoint`, `secondary` and
  `notify` are in the runtime layer for one reason: `Endpoint.tls` and
  `MasterSpec.tls` hold an `xot::XotName`, which is a
  `rustls::pki_types::ServerName` plus the operator's text. `rustls-pki-types`
  costs `web-time` and `zeroize`; `rustls` additionally costs `once_cell`,
  `ring`, `rustls-webpki` and `subtle`. Move `XotName` beside `tls_identity` —
  whose only dependency is already `rustls-pki-types`, and which needs no
  `tokio` today — and `xot` keeps the connector.

  **Five non-test sites** (`endpoint.rs:26`, `:39`, `:63`; `secondary.rs:23`,
  `:120`), one test helper and three in `xfr.rs`'s mocks. `XotName::parse` does
  not move, so §15's startup check is untouched. `notify` is the sharpest case:
  it links a TLS type solely to call `.is_some()` on it at `notify.rs:49` and
  refuse `+tls=` on `--also-notify`; it needs the bit, not the name.

  The alternative — moving the field off `MasterSpec` — costs 23 edits and
  contradicts `secondary.rs:126`, which says `for_member` is a method *because*
  `tls` is the field that would be forgotten. Declined on both counts.
- **67d. `tsig` already needs nothing from `rdns`, which settles 66c's shape.
  — acted on by #66c, which moved it.** The measurement held exactly: the move
  was a rename of paths and nothing else.
  Every `crate::` path in its production code resolves to `rdns-core`:
  `crate::error` and `crate::clock` and nothing else — checked by stripping the
  test module and listing them. So the module's whole dependency set is
  **`rdns-core` + `ring` + `base64`**, and core already carries `base64`. There
  are **no intra-crate references to untangle**; the only `rdns`-side mention is
  `test_records::nm` in its own tests.

  A client-only surface — sign a request, keep its MAC, check the reply — is
  `sign_request` (`:770`), `request_mac` (`:794`) and `check_response` (`:803`),
  costed at **≈575 of 1096 production lines**, of which **22 are `ring::hmac`**:
  the algorithm table, key parsing, the RFC 8945 record, the framing and the
  name and time helpers. What drops is the server and authorization half —
  `TsigKeyring`, `TsigSession`, `check_request`, `UpdatePolicy`, the zone scopes.

  `tsig.rs:3` gives the reason the module carries its own framing — "works on
  bytes, not a parsed `crate::DnsMessage`: name compression is a choice, so a
  re-serialized message is not the bytes that were sent" — and that reason is
  *why* it needs nothing from `rdns`. The proposal rests on it rather than
  arguing with it.
- **67e. Declined, with the numbers, so nobody re-derives them.** §18: a
  measurement taken and dropped is a measurement taken twice.
  - `dnssec.rs`'s verify/parse seam: **441 no-crypto lines against 90** — typed
    views, canonical form, `signed_data`, `key_tag`, the RFC 3110 key split,
    against `verify` and `ds_digest`. Declined because the no-crypto half's only
    consumers are `verify_rrset` and `dnssec_key::sign_rrset`, which are the
    crypto half — and `dnssec.rs` reaches nothing in `rdns` anyway, so a crate
    cut gets the whole module without the internal split.
  - `zone_signer`: **2 production lines of 1342** are the crypto (`:1240` signs,
    `:1083` hashes). Declined because parameterising over "a signer" makes the
    module generic over its own purpose, and because its header (`:4`) records
    that its output is judged by `verify_rrset`, `proves_nxdomain` and
    `proves_nodata` unmodified — §1's "judge output with the reader", which a
    split would cost.
  - `nsec_cache` (4 hashing sites), `dnssec_chain` (6 `verify_rrset` calls),
    `dnssec_validation_mode` (1) and `rfc5011` (3) all reach crypto only through
    `dnssec` and `dnssec_denial`, and each would end up generic over the thing it
    exists to do.
  - `logging::watch_anomalies` is `logging`'s only `tokio` reach, 18 lines,
    **2 callers**. Declined: `logging.rs:252` records that this facility spent a
    year write-only because the loop had no owner (#30m), and two copies is what
    §7 forbids.
- **67f. Two dead public functions, and a test fixture that would drag `sha1`
  into any new crate. — done 2026-09-15.** Found on the way; §18 says dead code is a finding and
  not litter, so it is filed before it is deleted.
  - `dnssec_denial::nsec3_owner_name` (`:51`, `pub`) has **no caller in the
    workspace** — the only other mention is a doc link at `denial_wire.rs:213`.
    Superseded by `nsec3_owner_name_at` (`:42`), which takes a `NameRef` and
    builds no `String`.
  - `dnssec_denial::nsec3_hash_in` (`:80`, `pub`) is called only by `nsec3_hash`
    (`:71`) in the same file. Public for no consumer.
  - `test_records.rs:4` says "Nothing cryptographic lives here" while `:87`
    calls `nsec3_hash_name`. The three NSEC3 fixtures want moving to
    `dnssec_test_util`, which already holds keys and signatures — **two `use`
    lines** (`dnssec_denial.rs:843`, `nsec_cache.rs:983`), those two being the
    only users. Without it, a crate cut's tests pull `sha1` back through the
    fixtures and the measurement lies.
- **67g. One finding outside the sweep's brief. — done 2026-09-15.**
  `security::ResponseLimiter::tracked` (`security.rs:372`) reads a poisoned lock
  as zero clients — `lock().map(..).unwrap_or(0)` — where the five decision
  paths above it all use `let Ok(..) else` with a commented policy. It is
  documented "for tests and diagnostics", so the stakes are low and the shape is
  still §4's.

**67a-c landed 2026-09-15, and the free set is 23 of 41** — measured with the
same pass that proposed them, not predicted. Three things the proposals could
not know without compiling, all cheap and all worth the record:

- 67a needed a constructor. `hash_wire` builds the value from the array it just
  filled, which a private field in another module no longer allows, so
  `Nsec3Hash::from_octets` exists — total, where `from_wire` on a known-good
  array would be an `expect` on an infallible path (§4). And `cargo doc` caught
  the upward doc link the pass predicted, which is the one claim in the recipe
  a compiler checks for free.
- 67c needed a *dependency*, not just a move. The pass said `tls_identity`'s
  "only dependency is already `rustls-pki-types`" — it reaches those types
  through `rustls`, like everything else here, so holding a `ServerName`
  without the TLS stack meant naming `rustls-pki-types` directly. It was
  already in the tree through `rustls`, so it costs nothing: `rdns` 55 packages
  before and after, both daemons 113. The type went to `endpoint` rather than
  beside `tls_identity`, because `endpoint` is what parses it and `xot` never
  imported `endpoint`, so there is no cycle to argue about.
- **The count was 24 predicted and 23 measured.** `notify` leaves the TLS stack
  and stays out of the free set, because it reaches `ring` through `tsig` — it
  signs the NOTIFY. A real crypto edge, and not the one 67c was about.

  Verified on both platforms, since all three touch modules one side compiles
  differently (§1): **1 186 passing on Windows and 1 206 on Linux**, clippy
  clean over `--all-targets` on both, `cargo doc` clean. The 20-test gap is the
  `cfg(unix)` half — the permission checks and `rdnsd`'s control socket — which
  is the same tell that number has always been.

**What 67f and 67g cost, and the one thing deleting turned up.**
`nsec3_owner_name` went, and `nsec3_hash_in` is private — and the deletion left
`encode_base32hex` with no caller outside `rdns-present`, which nothing would
have warned about because the crate split had made it `pub`. That prompted
counting the rest: **7 of the crate's public items had no user outside it**, so
they are `pub(crate)` again — most of the 8 that #67's decision unsealed,
clawed back. `parse_params`, `encode_base32hex_in`, `BASE32HEX_LOWER`,
`reversed_labels` and `record_line` stay public because `rdns` names them.

Re-sealing created two doc links from a public page to a private item, which
is §37's exact shape, and `cargo doc --no-deps` caught both — the third time in
two days that command has been the thing that noticed. Both are prose now
saying *why* the item is private.

The NSEC3 fixtures moved to `dnssec_test_util`, which makes `test_records`'s
"nothing cryptographic lives here" true for the first time: `nsec3` called
`nsec3_hash_name` fifty lines under that sentence. `ResponseLimiter::tracked`
recovers a poisoned lock instead of reading it as zero clients, with the
failure policy written down as the five decision paths above it already do.

**What this changes about the row.** The crate line was never the thing in the
way. 67a-c are about a dozen lines of moves that take the free set from 9 to 21
of 41 and cost no `Cargo.toml` a single edit; 67d says the one module `rdnsc`
needs is already shaped for a move. Whether any of it should *become* a crate
still turns on the binary-size figure this row is blocked on, which still needs
66a. The difference is that after 67a-c the question can be answered on its
merits instead of on accidents.

~~**Two shapes worth building rather than arguing** (§19, and #63h's precedent —
the recommended one lost): a third crate between core and `rdns` for wire plus
presentation plus transaction authentication, against simply widening
`rdns-core` and letting `ring` into it.~~ **Both built 2026-09-15** — for the
presentation half; the `ring` half is 66c's and untaken.
**Decided 2026-09-15: the fourth crate, `rdns-present`, and it is on `main`.**
Both shapes were built, measured the same way and run green; the branch that
lost is kept at `67-shape-core` with its own commit message, as #63h's were.

`rdnsc` with record presentation reachable, release, against 814 080 bytes and
34 packages today:

| | bytes | packages |
|---|---|---|
| **`rdns-present`** | **860 160** (+46 KB) | **35** (+1) |
| into `rdns-core` | 861 696 (+47.6 KB) | 34 (+0) |
| depending on `rdns` | 1 199 104 (+385 KB) | 72 (+38) |

**The size did not decide it.** The two shapes are 1.5 KB apart, and the only
figure that matters is that both are ~8x cheaper than letting `rdnsc` link the
server library — so the linker does *not* strip a dependency on `rdns` down to
what is called. That settles the refutation this row was filed with ("if that
is 50 KB then a new crate buys a manifest that reads better and nothing else"):
46 KB against 385 is the comparison, and the split earns its place.

**What decided it was a thing no argument had surfaced.** Seven `svcb` tests
round-trip through the zone *parser*, which is `rdns`'s. A dev-dependency back
on `rdns` carries them in the fourth-crate shape — cargo permits the cycle —
and does not in the other, because there the cycle runs *through the crate
under test*: cargo builds a second instance of `rdns-core`, and `crate::Rtype`
stops being `rdns::Rtype` (`expected rdns::Rtype, found codes::Rtype`). Those
seven had to leave the module they test. That is #20's rule broken by a crate
boundary rather than by anybody's decision, and it is the kind of thing §19
says only building finds.

Two smaller costs, the same in both shapes and worth knowing before the next
one: **8 `pub(crate)` items became `pub`**, which is #38's sweep in reverse;
and doc links stopped resolving upward — four in the shape that landed, six in
the other — every one caught by `cargo doc --no-deps` and rewritten as prose.
That is the cost that is invisible unless the command in the recipe is run.

Verified on both platforms after the merge: **1 186 passing on Windows and
1 206 on Linux**, clippy clean over `--all-targets`, `cargo doc` clean,
`cargo fmt --check` clean. `rdns`'s own lib count drops 733 to 714 on Linux
because 19 tests went to `rdns-present` with the code they test.

**What is left of #67.** 67d says `tsig` is already shaped for the same move —
its production code names nothing outside `rdns-core` — and that is 66c's
prerequisite, not this row's. 67f's dead code and 67g's poisoned-lock getter
are unrelated and still open. The layering table above is now two rows shorter
in practice: `denial_wire`, `svcb`, `dnssec_time` and `record_text` are
`rdns-present`'s, and what is left in `rdns` under "zone and presentation" is
the half that needs a `Zone`.

**The limits this row inherits.** §14: count what a dependency does at run
time, not how it reads in a manifest. §17: do not restructure on a smell — the
`rdns` library is large (zone, DNSSEC, resolver, cache, xfr, RPZ, metrics) and
that is a different complaint from this one, with no measurement behind it yet.
A split that makes the graph prettier and no binary smaller has bought nothing.

---

### 68. A socket test that binds a real port fails under a parallel suite — **filed 2026-09-15**

`rdns_transport::metrics_server::tests::a_server_with_nothing_to_wait_for_is_ready_at_once`
failed once during a `cargo test --workspace` run and passed on the two runs
after it, on three runs of its own crate's suite and on three of the module
alone. Not caused by the change it was seen under (#67's crate move touches
nothing in `rdns-transport`); seen there, so filed there.

~~It binds a listener and scrapes it over TCP, which is what makes it worth
having and also what makes it the one shape `CLAUDE.md` §10 warns about: under
a whole-workspace run every test binary is competing for ephemeral ports and
for the scheduler, and the assertion has no headroom.~~ ~~What would settle it
is reading `start()` and `scrape()` for where the wait is — whether the server
is accepting before the scrape connects.~~

**Both guesses were wrong, and the row's own instruction is what showed it**
(2026-09-16). Reading the twenty lines:

- **There is no wait to get wrong.** `start_with` binds the listener and *then*
  spawns `serve`, so a `connect` that beats the accept loop waits in the
  kernel's backlog rather than failing. The accept-before-connect race the row
  named cannot happen.
- **That test has no wall-clock assertion**, so "the assertion has no headroom"
  is about a different test — the only `Duration` in the module is
  `the_endpoint_stops_with_the_server`'s 3 s drain budget.
- **Ephemeral ports are not scarce here**, which was the third guess and the
  one a measurement kills outright: the box sits at ~3 320 sockets in
  `TIME_WAIT` against a 16 384-port dynamic range, and a whole `--workspace` run
  adds about **100**. Sampled every 5 s across a run: 3 320 → 3 422 → 3 374.

**Not reproduced.** 900 runs of the module (`--test-threads 8`), 600 of them
with four concurrent `cargo test --workspace` runs as load: **0 failures**. 200
more on Linux after the change below: 0.

**What was wrong and is fixed**: the test that failed is one of the two in the
module whose assertions printed *nothing* — no body, and `scrape`'s three
`expect`s named neither the failing call's error nor the address. One run in
nine hundred failed and left no evidence, which is why the row could say the
failure mode but not the failure. Every assertion carries its body now and
every socket call names itself; the next occurrence says which of connect,
send, read or the status went wrong. **Left open** on that footing: there is
one unexplained failure and no explanation, only a smaller cost to seeing the
next one.

**A second sighting, 2026-09-20, in a different crate and with no name
captured.** One `cargo test --workspace` run reported `rdnsd` at 190 passed and
1 failed where every other run reports 191 and 0. Thirteen further workspace
runs and a `-p rdnsd` run were clean. The name was lost to the *reader*, not to
the test — the run was filtered to `^test result` lines — which is the same
evidence failure the paragraph above fixed for one module and is worth
repeating as advice: never filter a suite run down to its totals when the point
is to catch something rare.

**Two findings on the way out**, both in the file the row points at and
neither the flake: **#69**, every accept loop in the crate treats any accept
error as fatal while the UDP side has `recv_error_is_transient` and a written
reason; and **#70**, the module header claimed two hyper behaviours that hyper
does not have.

---

### 69. Four accept loops end on any error; the UDP side has a helper for that — **filed and closed 2026-09-16**

`tcp.rs:144`, `tls.rs:221`, `https.rs:108` and `metrics_server.rs:66` all spell
the accept the same way:

```rust
accepted = listener.accept() => accepted?,
```

so any `Err` returns from `serve`, and the transport stops accepting for the
life of the process. `rdns_transport::recv_error_is_transient` exists because
`CLAUDE.md` §4 made exactly this argument about `recv_from` — "anything a
remote party can provoke has to be recognized here or it is a remote kill
switch" — and it is applied at two call sites, both UDP (`rdnsd/src/main.rs:1238`,
`rdnsr/src/serve.rs:54`). The accept loops have nothing. §7's shape: the
reasoning was moved into a helper and the four loops that were not the one it
was written for never called it.

~~**Filed with no remedy, because the remedy is the unchecked part.**~~ Filed
that way and then both measurements were taken the same day, which is what the
remedy needed:

- **A remote party cannot provoke it, on either platform.** The provocation is
  an RST between the handshake and the accept: `SO_LINGER 0` on four clients
  that connect and drop against a listener that is not accepting yet. All four
  came back from `accept` as an ordinary `Ok`, on Windows and on Linux; the
  reset shows up later on the read. So the half of §4's rule that names a
  *remote kill switch* does not apply here, and the finding as filed — which
  leaned on it — was wrong about why it mattered. (`socket2` turned out to cost
  no package, being already in the lock file under `quinn`; it is not a
  dependency now either, because the probe is not a test.)
- **Descriptor exhaustion does, and needs nobody.** Under `ulimit -n 128`,
  `accept` returns **`EMFILE`** — `ErrorKind::Uncategorized`, raw 24, so no
  portable kind sees it, exactly like WSAEMSGSIZE. Windows could not be made to
  reach it at all: 100 000 handles opened without a failure. The condition is
  ordinary — 128 connections per loop across TCP, DoT, DoH and the scrape
  endpoint is over 400 descriptors before the zone files and the resolver's
  outbound sockets, against a 1 024 soft limit — and it is *transient*, clearing
  as connections close.

**What it cost.** Both daemons run their accept loops in a `JoinSet` whose first
finished task ends the process, so `accepted?` on one `EMFILE` did not stop one
listener — it stopped the server, every transport at once, on a condition that
would have cleared by itself.

**Provoked, not read** (§4). A `tcp::serve` with one descriptor left and a
connection pending: against the old code the probe's next write fails —
`tcp.rs:405`, connection reset, the loop is gone — and against
`survive_accept_error` the same probe answers. The probe is not committed: it
needs `ulimit -n` and would open two hundred thousand files where CI's limit is
high. What is committed is the classification, three tests, including that
`EMFILE` is recognized by its raw code and by no kind.

**The fix is one shared function** (§7), `survive_accept_error`, called at all
four sites: aborted-connection kinds retry at once, exhaustion logs and sleeps
100 ms first — a bare `continue` on `EMFILE` spins a core — and everything else
is still fatal, because a listener that cannot work should not become a loop
saying so ten times a second forever.

---

### 70. The metrics endpoint does not enforce RFC 9112 §3.2, and its header said it did — **filed and closed 2026-09-16**

`metrics_server.rs`'s header claimed that folding onto hyper (#42c) changed
"two behaviours, both toward the RFC": a `Host`-less HTTP/1.1 request getting
400 per RFC 9112 §3.2, and a request line over 8 KB getting 431. Both were
estimates of somebody else's code, never run. Measured:

| claimed | actual |
|---|---|
| no `Host` on HTTP/1.1 → 400 | **200**; hyper does not look |
| request line > 8 KB → 431 | **414**, and past 64 KiB — hyper's read buffer. 60 000 bytes is an ordinary 404 |

Four tests in that same file send HTTP/1.1 with no `Host` and assert 200, so
the file disproved half of its own header on the day it was written. The header
is corrected and both behaviours are pinned by
`hyper_serves_what_the_header_used_to_claim_it_refused`.

~~**What is left is a decision, not a defect.**~~ **Decided by the owner and
taken 2026-09-16.** The argument against it was that the endpoint has no
virtual hosts, which is what the MUST protects, and that enforcing it turns
`printf 'GET /metrics HTTP/1.1\r\n\r\n' | nc` — an operator's probe — into a
400.

**Taken 2026-09-16, and the section is three MUSTs rather than the one the row
read.** §3.2 in full: "A server MUST respond with a 400 (Bad Request) to any
HTTP/1.1 request message that lacks a Host header field **and to any request
message that contains more than one Host header field line or a Host header
field with an invalid field value**". Measured before anything was written,
because this row exists to correct estimates of somebody else's code: hyper
answers **200** to all three — no `Host`, two `Host` lines, and `Host: a b`.

`bad_host` refuses all three now. The third is delegated to `http`'s own
authority parser rather than spelled out here, because "invalid field value" is
§3.2's `uri-host [ ":" port ]` and a second implementation of that grammar is
what §7 is about.

**The count the row gave was wrong and §18's rule caught it**: "changing four
tests" was six tests and eleven requests, every one of them an
`HTTP/1.1\r\n\r\n` with no `Host` — which is also the measurement that says how
easily this would have gone unnoticed, since the whole suite was written
against an endpoint that did not look.

**What it costs is what the row said**, and the refusal pays it back: a
hand-typed `printf 'GET /metrics HTTP/1.1\r\n\r\n' | nc` is now a 400 whose
body names the spelling that works. §3.2 is about HTTP/1.1 alone, so
`GET /metrics HTTP/1.0` needs no header at all — asserted, not assumed. `curl`,
Prometheus and the `image` job's probes all send a `Host` and are unaffected.

---

### 71. A forty-record change rebuilds a zone and re-reads a file — **filed 2026-09-16, closed 2026-09-19**

Out of 57e, which took the wire down to what actually changed and left
everything after it sized by the zone. Measured on the development machine,
release, a million-rule QNAME feed
(`cargo test --release -p rdns --test rpz_install -- --ignored --nocapture`):

| applying a forty-rule change at 1M rules | ms |
|---|---|
| the difference off the wire and assembled | ~~about 7~~ **below the noise** |
| `ixfr::Patch::apply`, ~~rebuilding~~ **copying and editing** the zone | ~~801~~ ~~793~~ ~~445~~ ~~372-395~~ ~~138-146~~ **44.3** |
| serializing, writing, and putting the zone in force | ~~1 351~~ ~~1 200-1 420~~ **526** |

The first row is now a *nothing* rather than a small number: the whole IXFR
round trip is 453 ms and applying an **empty** difference sequence to a zone
this size is 445-458, so the wire and the assembly are smaller than what
separates two runs of this harness. Same conclusion as the 7, at a size where
the subtraction no longer has a sign. Both halves fell together after 71d and
the subtraction is still nothing: 383-395 against 372-395 on 2026-09-18.

The second row halved again on 2026-09-16, and that is **71c**: the rebuild was
growing a two-million-entry index from empty when both counts were sitting in
the zone it was rebuilding; 71d took the last 38 ms off it, and **71a** took
the rebuild away on 2026-09-19 — the zone is copied and edited now. **71e then
took the copy**, the same day: a zone's owner names and its RDATA are one arena
each, so the copy is a memcpy and six allocations rather than two million.
**801 ms as filed, 44.3 now**, of which 37.5 is the copy. The third stopped
being a band when it stopped containing a parse (**71f**): it is 247 ms of
serialization, a 38 MB write, 21 ms to read the file back and digest it, and
41 ms to index.

Only the first is the size of the change. ~~The third is shape A's trade and
not a defect — the file is the store (#57d), so an install serializes a zone
this process holds and parses it back, which is what buys a restart its rules —
and it is in the table so that 71a's number is not read as the whole cost.~~

**Half of that was wrong, and it is the largest thing this row turned out to
hold.** What buys a restart its rules is the *write*; the parse back was this
process re-deriving a zone it was holding, 613 ms of it. Putting it in
the table so 71a would not be read as the whole cost is what made it visible —
and then the sentence said "not a defect" about a row nobody had decomposed.
Taken as **71f**. The property it rests on — that the zone written and the zone
the file parses back to are one zone — turned out to be asserted nowhere: the
line that looked like it compares record *counts*. It is a test now, and the
row says how that was found.

**The struck figures were measured against themselves**, and finding that is
71b's by-product rather than its point. `rpz_install.rs` holds three
`#[ignore]`d million-rule measurements and the recipe in its own module doc
selects all three; libtest runs what a filter selects in parallel, so every
number this row and 57e recorded was taken with two other million-rule runs on
the machine. It is #64b's defect exactly, found there for the same reason and
fixed there with a turnstile — which `rdnsd`'s dispatch tests had and this file
did not (§7). The turnstile now lives in `rdns_core::testutil::one_at_a_time`
and both call it. The re-measured column above is what these cost with the
binary to themselves; the *shape* of the row is unchanged, which is why this is
a correction and not a retraction.

- **71a. `Zone` cannot be edited, so any change rebuilds it — closed
  2026-09-19.** **386.9 ms to 146.3** for a forty-rule change at a million
  rules, which takes the whole IXFR round trip from 402 to 149. A throwaway A/B
  in one run of the committed harness, as 71b's and 71e's were; the column that
  stayed reads 138.2-146.3 over four runs, of which the copy is 138.3-143.0.

  As filed: `Patch::apply` walked every record and `add_record` folded a key
  and filed a position for each, because the index holds *positions* into the
  record vector — which is why removal had no API, and `ixfr.rs` said so.
  **No remedy was claimed**: "it is a core type's shape and its call sites, not
  a loop."

  **The number to beat is 445 ms, not 793**, and the difference is why this row
  was filed a size too large. ~~801~~ ~~793~~: the first was contention (the
  section head), and **71c** took 793 to 445 with a capacity hint. This row
  called the problem "a core type's shape and its call sites, not a loop", and
  the larger half of it turned out to be neither — one `reserve` at one line.
  What is left at a million records, measured after 71c:

  | | ms |
  |---|---|
  | `apply_changes`, whole | ~~445~~ ~~**407**~~ **138-146** |
  | of which cloning every record of the base | ~~about 120~~ **138-143** |
  | of which the index: 2M names hashed, filed, and their ancestors walked | ~~320~~ ~~**~280**~~ **gone** |

  ~~So the type change is worth ~407 ms here and 4.4 s in #65, and **the clone
  is not the half worth taking** — the same result #64g got from the signing
  side, now measured from this one. A remedy that removes the rebuild removes
  both; one that only stops the clone buys 30% of this row and nothing of
  #65's.~~

  **The last sentence is exactly backwards about what would be left, and that
  is the useful part.** "The clone is not the half worth taking" was true of
  the 407 ms as it stood and became false the moment the rebuild went: a remedy
  that removes the rebuild does not remove the clone, it *promotes* it, and the
  copy is now 95% of what an apply costs. The two were read as one because both
  are O(zone) and a rebuild was assumed to subsume a copy; they are two
  different O(zone) costs, 120 ms apart, and only one of them is a memcpy. What
  is true and survives is the #65 half — its five shared passes are 4.4 s at a
  million records and nothing here touched them.

  **71d changed the arithmetic this row is decided on, and the direction is
  towards copy-and-patch.** Before it, a `Zone::clone` was 318 ms against a
  445 ms rebuild — 71% — which is why an earlier reading of this row called
  tombstones dead on arrival: no shape that *copies* could beat one that
  rebuilds. After it the clone is 120 ms and dropping the old one 43, so
  copy-and-patch is 163 ms against 407, and the family is alive again. That is
  the prediction this row closed on, and it held: 146.3 against 386.9 measured,
  where the arithmetic said 163 against 407.

  **That framing was wrong twice, both times in the direction of the work being
  larger than it is.** 71c had already taken the larger half of the number with
  one `reserve`, and the row said so. The rest is two things, neither of them a
  call site: an index entry counts the names directly below it, which is what
  makes a name removable at all; and `swap_remove` leaves exactly one stale
  position, which the index reaches by that record's own owner name.
  `Zone::records` is untouched, no public signature changed, and the diff is
  `zone.rs` and `ixfr.rs`.

  ~~**Whoever takes this row takes 71e first**, or measures the same wall
  twice.~~ **The order is the other way round.** Taken alone this is 2.6x, and
  71f had taken away 71e's last live caller — this row is what gives it one
  back. 71e is now worth 138-143 ms of the 138-146 this leaves.

  **Tombstones were the shape the row named** — "worth about 2.5x rather than
  nothing", which the 2.6x measured is — **and they are not needed.** A
  tombstone keeps record order and costs `records()` its slice, which is the
  98-error blast radius 71e counted. `swap_remove` costs the order instead, and
  the order was load-bearing nowhere: the serializer writes the apex SOA itself
  and then the rest, and an AXFR brackets its own (RFC 5936 §2.2, which puts no
  constraint on the middle). The three comments that claimed load order are
  corrected rather than left to be true-ish (§4).

  **The positions were not the hard part; the empty non-terminal was.** A name
  is in the index because it owns records or because something below it does
  (RFC 4592 §2.2.2), and dropping the last record at a name may not drop the
  name while a descendant still needs it. Left behind, it answers NODATA where
  the zone has nothing, and an RFC 8020 resolver caches that for the subtree.
  **Direct children, not descendants**, because that is the count an insertion
  keeps in O(1): a new name credits its parent and only a parent that was
  itself new walks on up, which is the rule `note_non_terminals` already had.
  It fits in `len`'s padding, so the table is the same 32 bytes.

  **The measurement that could refute it did, on a question the row never
  asked.** Everything under the index is append-only, so applying deltas
  forever grows a zone that is not growing: a difference sequence spells a
  changed record as a deletion and an addition (RFC 1995 §2), so the name's
  octets are appended again every publication and a name that falls back to one
  record leaves its position list behind. 4 000 changes to a 1 000-name zone
  took the arena from 24 031 octets to 120 031 and the spill list from 1 entry
  to 101, with the entry count, the record count and every answer unchanged —
  invisible except as a process that grows for a year and then is restarted.
  A rebuild when removals reach half the record count reclaims both and
  re-shares the arena suffixes an empty non-terminal borrows, which a
  compaction written for the purpose would not. **Against `records` and not the
  entry count**: a zone of one name with a million records would otherwise
  rebuild all of them on every removal, which is the O(n²) this row exists to
  remove. Amortized O(1) a removal, and the test is a ratio (§10) — four times
  the rounds and the same peak.

  **One by-product worth the trip.** Two counters for the two append-only
  vectors took `Zone` from 176 bytes to 192, and `xfr::Refresh` — which holds
  one by value and sat *exactly* at clippy's 200-byte `large_enum_variant`
  threshold — from 200 to 216. A field added to `Zone` is a field added to
  every enum that carries one, and that lint is the only thing in this tree
  that says so. One `u32` counter does both jobs, because the rebuild is what
  has to be paid for and it rebuilds both vectors, and it fits in the padding
  `Shortcuts` leaves: 176 and 200 again.

  **What this does not touch**, and the reason the row named them: **#65**'s
  unowned half, five shared passes at 4.4 s a million records, and what
  **#64g** measured on its way out — removing `rrsets_of`'s clone took that
  pass down 25% and the total nowhere, because the clone was laying the RDATA
  out in the order the signing loop reads it. Both are about the signer's
  passes over a zone, not about applying a delta to one, and a remedy for
  either still has to keep the order its reader walks in.

  Verified by provoking each half (§1): the removal tests fail against a build
  with the ancestor prune removed (three of them) or the position repair
  removed (three), the denial-chain test against either half of its repair, and
  the bound test against the rebuild — each reverted, run, restored. The
  patch-applied zone is compared against a *parse* of the same records rather
  than against the rebuild it replaced, record by record and name-kind by
  name-kind, because a parse is the one reference that cannot share a mistake
  with it.

  ~~**71b closing changes nothing about this row**: the `Arc<PolicyZone>` it
  landed shares a zone that nobody edits, which is the same fact stated the
  other way round.~~ Still the same fact, and now worth saying the other way:
  a `PolicyZone` is shared behind an `Arc` and a patch builds a *new* zone from
  a copy, so nothing here edits a zone anybody else can see.

- **71b. One feed changing re-reads every feed — filed 2026-09-16, closed the
  same day.** `PolicyStore::reload` was `PolicyZones::load(&self.feeds)`:
  all-or-nothing over the whole set, which is right for what it was written for
  — a half-written file must not lift a block (§4) — and which cost O(every
  feed) for a change in one. 57e's probe means it happens per *publication*
  rather than per REFRESH, so the row was worth less than it was the day before
  it was filed. The shape the row named is what landed: `PolicyZones` holds
  `Arc<PolicyZone>`, and a reload hands a feed nobody touched straight back.

  **The all-or-nothing property is kept and is now per feed**: every file is
  still read and every changed one parsed before any of the set is built, so a
  half-written feed still leaves the previous set whole.

  **What it buys**, on `reloading_a_set_when_one_feed_publishes` — three feeds,
  one publisher, release, the development machine. The `cold load` column is
  the old behaviour, not a separate run: a reload *was* a cold load of the
  whole set, so that is what the other two are against.

  | rules per feed | cold load | none moved | one moved |
  |---|---|---|---|
  | 10 000 | 29.1 ms | **0.6 ms** | **17.0 ms** |
  | 100 000 | 191.9 ms | **6.2 ms** | **71.6 ms** |
  | **1 000 000** | **2 200 ms** | **62.0 ms** | **781 ms** |

  So a SIGHUP over a quiet set is 35x cheaper and one publication into a
  three-feed set is 2.8x, and both ratios grow with the number of feeds.

  **The test is the file's bytes and not its `stat`**, which is the measurement
  that decided the shape: reading and digesting a million-rule feed is 21 ms
  against the ~720 its parse and index cost, so the honest test is 3% of what
  it replaces — #64f measured 1.8% for a zone file. A `stat` is 0.08 ms and
  cannot see an edit that preserves length and timestamp, and a missed edit is
  the operator's change silently not taken — the exact failure a re-read exists
  to prevent (§4). #64f made the same argument for `rdnsd` and this is the same
  code now: `rdns::zone::FileDigest` was `rdnsd`'s `digest_of` plus its
  `is_self_contained`, moved on the third caller (§7, `origin_from_path`'s
  precedent).

  **An `$INCLUDE` is never kept**, for #64f's reason: a digest of a feed says
  nothing about a file it includes. The type carries that rule rather than each
  caller re-asserting it — `FileDigest::of_self_contained` returns `None`, so a
  caller cannot skip work on the strength of a digest that could not speak for
  the file (§17). Both daemons' tests for it fail against a version that
  returns `Some`.

  **Two things found on the way**, both in the moved code and both outside what
  the row named:

  - The `$INCLUDE` scan uppercased every line, which is an allocation per rule.
    `eq_ignore_ascii_case` on the head instead took the quiet-set reload from
    162 ms to 62, and `rdnsd`'s own unchanged-reload figure (#64f, which
    recorded **39 ms** at a million records) to **15.6 ms** on the same
    harness. #64f's table is left as it was measured.
  - The query path pays nothing for the `Arc`. Four feeds of 200 000 rules,
    timed against the pre-change tree: a miss is 446-476 ns before and
    452-474 after, a hit 252-258 against 255-263. There is no RPZ benchmark to
    hang this on and the A/B was a throwaway, which is why the numbers are here
    rather than in a committed harness.

- **71d. The index key was a `Box<[u8]>` per name, and `std`'s `HashMap` is why
  — filed and closed 2026-09-17.** **`Zone::clone` 318 ms to 120** at a million
  records, and a query miss **114 ns to 76**. Out of asking what 71a's copy is
  made of, and the answer was: the key type.

  A `HashMap` reaches its key only through `Borrow`, so the key must own and
  hash its own bytes. That is why the index was keyed on `Box<[u8]>` and not on
  `Name` — `rdns_core::name_keys` makes the same argument for the same reason,
  and `Name` is a `Box<[u8]>` anyway, so keying on it would have cost the same
  allocation and lost borrowed probing as well. **The owned key is an artifact
  of the collection, not of the name type and not of the data.**

  `hashbrown::HashTable` takes the hash and an equality closure from the
  caller, so an entry can be a range into an arena and nothing allocates per
  name. It is the API `std` keeps behind the unstable `hash_raw_entry`.

  | at 1M records | before | after |
  |---|---|---|
  | `Zone::clone` | 314-321 ms | **119-122 ms** |
  | dropping that clone | 104-108 ms | **43-44 ms** |
  | query miss | 114-121 ns | **75-77 ns** |
  | query hit | 381-392 ns | **213-254 ns** |
  | `ixfr::Patch::apply` | 445 ms | **407 ms** |
  | AXFR assemble | 1 160 ms | **1 132 ms** |
  | reload set, one publisher | 781 ms | **710 ms** |
  | `size_of::<Zone>()` | 168 B | 176 B |

  **The dependency costs nothing and that was checked, not assumed.**
  `hashbrown 0.17.1` was already in `Cargo.lock` through `indexmap` <- `toml`
  (#15) and already linked into both daemons, so the lock gains **one line** —
  an edge from `rdns`, not a `[[package]]`. **218 packages either side**, which
  is the number §14 says to count.
  `default-features = false`, because every probe passes its own hash and the
  default hasher would be dead weight.

  **FxHash, not SipHash, and the argument is about who can insert.** A weak
  hash is dangerous where an attacker chooses what shares a bucket; here every
  key is one of the operator's own zone names and a query only *probes*, so a
  chosen QNAME reaches at worst the longest collision cluster among names
  already loaded — a load-time property no packet can grow. Measured: Fx
  collides on 50 400 of a million-rule feed's 2M names (**2.5%**, against zero
  for FNV-with-avalanche) and the longest cluster is **2**.

  **Four shapes were built before this one** (§19), on 2M entries:

  | | clone | probe 200k |
  |---|---|---|
  | `HashMap<Box<[u8]>, Slot>`, SipHash — what this replaced | 244 ms | 47 ms |
  | the same, FxHash | 242 ms | 20 ms |
  | a 40-byte inline key | 61 ms | 33 ms |
  | arena + hash key, `enum` bucket | 42 ms | 28 ms |
  | arena + hash key, POD entry — **this** | 11 ms | 15 ms |

  The second row is the one worth keeping: **the whole copy cost is the
  per-key `Box`**, and the same table keyed on a `u64` clones 41x faster.
  Nothing about the table's shape matters.

  **The hand-rolled version had a bug and the dependency is what removed it.**
  Before reaching for `HashTable`, the arena index carried its own collision
  chain; on an insert it handed back the *incumbent's* slot, so two names'
  records were filed under one of them — 236 of the 10 000 names
  `bench_zone_lookup` builds came back with two records. The logic was read
  through twice and called correct both times; the benchmark caught it on the
  first run (§19: arguing costs more than compiling).
  `an_index_keeps_two_names_that_hash_alike_apart` is that pair, and it fails
  against an index that trusts the hash, as does `bench_zone_lookup`.

  **`usize` offsets, not `u32`, at 6% of the clone.** `u32` was 114 ms against
  120 and `names.len() as u32` silently truncates on an arena past 4 GB —
  reachable on a zone of a few hundred million names, which is well after
  `records` has exhausted the machine but is not never. `usize` removes the
  truncation instead of guarding it, and a guard on a load path would have to
  be a panic or a new error on `add_record` (§2's "`as` is a bug until proven
  otherwise", §4 on what a load path may do).

  **Allocation counts moved *up* on a small zone and that is the trade**: 87 ->
  88 to parse an eight-record zone and 566 -> 570 to sign one, because the
  arena is one allocation a zone pays whatever its size, against two per name
  it stops paying. The reason is written beside both assertions (§17).

  **What this does not do is close 71a.** A rebuild is 407 ms, not O(delta),
  because `Patch::apply` re-hashes every name rather than copying the index —
  and nothing on any measured path clones a `Zone` today. What it changes is
  the arithmetic 71a is decided on: see that row. The next stage is 71e.

- **71e. `ZoneRecord` is two allocations per record — filed 2026-09-17, closed
  2026-09-19.** **`Zone::clone` 97.6 ms and 2 000 004 allocations to 18.7 ms
  and 6**, and dropping the copy 35.5 ms to 4.0, at a million records
  (`rdns/tests/record_storage.rs`). On the path that pays for it, applying a
  forty-rule change to a million-rule feed is **143.4 ms to 44.3**, of which
  the copy is 142.3 to 37.5 — the feed's names are twice the length of that
  harness's, which is the whole of the difference. What
  is left of the copy after 71d: `Name(Box<[u8]>)` and
  `RecordData { rdata: Box<[u8]> }` are one heap allocation each, so cloning a
  million-record zone is still two million of them. That is **~108 ms of the
  120** `Zone::clone` now costs — the index is the other ~12, and it is a
  memcpy of two vectors. Re-measured on its own harness the next day, on a zone
  of shorter names: 79-82 ms of 96-99, plus 32-38 to drop the copy. The same
  85%.

  The same remedy applies and it is the one `CLAUDE.md` §13 already argues for
  the name compressor: one arena plus ranges. It would take the clone to
  roughly the 11 ms the index table measures.

  ~~**No remedy claimed, because the blast radius is real and unmeasured here.**~~
  **Both measured 2026-09-18**, and the remedy the row named is the one to take
  *if* the row is taken at all — which is now a smaller if than it was. Whoever
  takes it should still read #64g first: the clone it removed was buying the
  signing loop its RDATA order, so an arena has to be laid out in the order the
  reader walks, not the order the writer wrote. That is the same sentence #65's
  unowned half needs.

  **The shapes, built and timed** (1M records, release, the development
  machine; `rdns/tests/record_storage.rs` holds the two that measure the real
  type, and the four-way comparison was a throwaway A/B as #71b's was):

  | how a record holds its two byte strings | fill | allocations | held | clone | drop | `size_of` |
  |---|---|---|---|---|---|---|
  | a `Box` per field — ~~**today**~~ **until 2026-09-19** | 80.4 ms | 2 000 001 | 64.7 MiB | 83-87 ms | 32-33 ms | ~~40 B~~ **48 B** |
  | an `Arc` per field | 97.4 ms | 2 000 001 | 99.2 MiB | 12-13 ms | 10-11 ms | 40 B |
  | 40 octets inline, longer on the heap | 34.0 ms | 1 | 99.2 MiB | 16-19 ms | 4.3-4.4 ms | 104 B |
  | 23/15 octets inline | 62.7 ms | 900 001 | 81.6 MiB | 54-56 ms | 17 ms | 64 B |
  | **one arena plus ranges** | 22.3 ms | 41 | 58.0 MiB | 3.8-4.1 ms | 0.9-1.0 ms | 24 B |

  The two `size_of`s in the first row were wrong by eight: an owned
  `ZoneRecord` is 48 bytes, not 40, and so is the `ZoneRecordRef` that replaced
  it — `Name` is 16 and `RecordData` 24 with its `Rtype`. The arena row's 24 was
  right and `Stored` measures 24.

  The arena is the only shape that wins on every axis, so there is nothing to
  argue about the *shape*. `Arc` buys the copy and costs 34 MiB and a slower
  fill; inline at 40 costs the same memory and a 104-byte record on the query
  path; inline at 23/15 is neither, and the feed it was measured on has 900 000
  of its million names over 23 octets.

  ~~**The blast radius, counted the way 63a counted its own** — seal
  `Zone::records` and let the compiler name what cannot be done without it:
  **98 errors in `rdns` across 13 files**, and ~21 more in the binaries, which
  stop compiling behind it.~~ **It came out at 66 in `rdns` and 12 in the
  binaries**, and the difference is the one thing this row got wrong in a
  useful direction: the count was taken by *sealing* `records`, which is not
  what the change had to do. `Records<'_>` is a view with `len`, `is_empty`,
  `get`, `iter` and `IntoIterator`, so every reader that counted a zone or
  walked one reads the same — and the row's own "41 of those sites are
  `.len()`/`.is_empty()` and survive an iterator" is the sentence that should
  have said so. A blast radius measured by deleting an API is an upper bound on
  one measured by replacing it (§19: the measurement that could refute the
  finding).

  The rest of the count held. A borrowed record means a borrowed `RecordData`,
  and that type's fields are sealed in a module of its own *on purpose* (§17),
  so `RecordDataRef` lives there with it and every read-only accessor moved onto
  it — `RecordData` delegates, so the offset arithmetic that reads an SOA's
  SERIAL exists once (§7). 14 signatures took `&RecordData` and take
  `RecordDataRef<'_>` now.

  **The arenas are sealed by their own door, not by a `pub(crate)` hole.**
  `NameArena` lives in `name.rs` and `RdataArena` in `record_data.rs`, because
  handing out a `NameRef` over octets an arena holds means minting one without
  `NameRef::from_wire_slice`'s label walk — and a `pub(crate)` constructor for
  that would be open to every module in `rdns-core` rather than to the one
  caller. The only way *into* an arena is a checked value, so what comes out was
  checked on the way in. The span carries the TYPE for the same reason: two
  fields a caller could pair up wrongly is what §17 opens with.

  **One bound had to change.** `signed_data` and `verify_rrset` took
  `R: Borrow<RecordData>`, which cannot reach a `RecordDataRef` — there is no
  `RecordData` for it to hand back a reference to. It is `R: AsRdata` now: the
  same requirement stated as what the callers do with it, one method, two
  impls. #64g's default type parameter still keeps it off the 40 call sites
  that own their RDATA.

  **And the measurement that could refute the row did, on the load path.**
  Parsing a million-rule feed is 613 ms and **8 000 062 allocations** — eight
  per record, of which the record's own two are a quarter. So an arena is worth
  ~60 ms of a 613 ms parse, not the load path's problem, and what is left of
  71e's value is the copy: 96 ms of `Zone::clone` plus 37 to drop it, on a path
  ~~**nothing measured takes today** (71d said so and it is still true). 71f
  took the parse out of the install altogether, so 71e no longer has a live
  caller at all — its whole case is 71a, and 71a's is the 372-395 ms rebuild.~~

  ~~**So: open, with the remedy named and priced, and nobody should take it
  before 71a is decided.**~~ **71a closed first and handed this row its
  caller**, 2026-09-19. Applying a delta is a copy and an edit now, so the copy
  that had no live caller was the only thing left on the path.

  **The shapes table's 3.8-4.1 ms is the records alone, and `Zone::clone` is
  18.7.** The difference is the index, which #71d already made a memcpy of two
  vectors: two million entries at 32 bytes is 64 MB to copy, against 24 for the
  records, 24 for the name arena and 9 for the RDATA. Six allocations for the
  whole zone. That is memcpy-bound, and the table was right about the part it
  measured — a row that quoted it as the *zone's* figure would have been the
  §19 mistake in the other direction.

  **What it cost, and both numbers are real.** The answer path's whole answer is
  **460.3 ns to 430.1, −6.1%** — one allocation fewer, because `ZoneRecordRef`
  and `ResourceRecord` are both 48 bytes and `Vec`'s in-place collection now
  reuses the vector `Zone::query` returns where a `Vec<&ZoneRecord>` at 8 bytes
  an element could not. The *lookup* alone is **+5.4%** (54.2 ns to 57.1 on a
  10k-record zone), because a 48-byte `ZoneRecordRef` is built per record where
  an 8-byte pointer was copied. Net −6% end to end, and the two are in the
  commit message because quoting only the first would be a benchmark chosen to
  agree (§1).

  **Memory, which the row had not asked about**: a parsed million-record zone
  is **228.2 MB to 210.2** (239 to 220 bytes a record), a signed one **732.5 MB
  to 658.0**, and `rdnsd`'s ten thousand small zones 24.7 MB to 24.0
  (`rdns/tests/scale.rs`). `Stored` is 24 bytes against the owned
  `ZoneRecord`'s 48, exactly as the shapes table said.

  **The load path did not move and that was the row's own prediction**: a
  million-rule parse is 599.8 ms before and 588.8 after, 8 000 062 allocations
  and 8 000 065. The parser builds an owned `Name` and `RecordData` per record
  and `add_record` copies both into the arenas, so the record's two allocations
  are still made — by the caller — and one copy is added. That copy is
  **#72**.

  The other six allocations per record are their own question and ~~nobody has
  asked it~~ **#72 asked it on 2026-09-19**: on `scale.rs`'s zone there are
  seven in all, five of them came out, and the largest was `add_record`'s own.
  This row is not it. Two of them are **#72**.



- **71f. The install parsed back the zone it was holding — filed and closed
  2026-09-18.** **1 141-1 261 ms to 526** at a million rules, which is the third
  row of the table above and the largest number this section had. The band is
  the old route's: it writes 38 MB and then parses it, and two runs an hour
  apart read 1 141 and 1 261. The new one read 526.0 and 526.2.

  A transfer serialized its zone, wrote the file, and asked for a reload; the
  reload read that file and parsed 38 MB into a zone byte-for-byte identical to
  the one the transfer task was still holding. 613 ms of re-derivation per
  refresh, under a comment calling it shape A's trade.

  **It is not shape A's trade.** What buys a restart its rules is the write.
  57d's A and B were framed as write-and-re-read against install-in-memory, and
  the third thing — write *and* install — was not one of the three. The file is
  still the store, still written first, still the only thing that survives.

  **The digest is the whole mechanism, and it already existed.** `PolicyZone`
  has carried the digest of the bytes it was read from since 71b; a zone
  written out now carries the digest of the bytes written, and
  `PolicyStore::offer` keeps it for the next reload. The reload still reads
  every file — a `stat` cannot see an edit that preserves length and timestamp
  (§4) — and takes the offered zone only where the file's bytes are still those
  bytes, so a feed a cron job rewrote in between is parsed as it always was.
  One door: the offer is consulted inside `PolicyZones::reload`, beside the
  held set, and is all-or-nothing with it.

  **`rdnsd` has done exactly this all along**, which is what makes it §7 rather
  than an idea: its secondary writes the zone file and then calls `install_zone`
  with the zone it fetched (`replication.rs`), and its UPDATE path remembers the
  digest of what it wrote so the next update need not parse (#64b). One install
  path of the three re-read its own output, and it was the newest.

  **Verified by provoking it** (§1, §4): the regression test asserts the reload
  parsed *nothing* and installed one feed, and fails with `reread` 1 against
  the version before this; a second test rewrites the file behind the offer and
  asserts the parse happens and the file's rules win; a third refuses a path no
  feed reads; a fourth compares the installed zone with a parse of the same
  file, field by field.

  **That fourth one is here because the row's own evidence was not what it
  said.** This was filed on `rpz_install.rs`'s "the two shapes must install the
  same zone, or the comparison is of two things" —
  `assert_eq!(a_zone.records(), b_zone.records())`, at a million rules, since
  57d. `PolicyZone::records` returns a **count**. The assertion compares two
  `usize`s and five trigger counts, and `ZoneRecord` has no `PartialEq` at all,
  so the line could not have meant what it was read as. Caught by writing the
  comparison the row claimed already existed and having it refuse to compile
  (§4: never state what a function does without opening it — including an
  assertion, and including one being cited as a reason to act). The comparison
  is field by field and not a round trip through the writer, which would hide
  anything the writer drops.

  **What it does not do**: the serialization (247 ms) and the write are what is
  left, and both are the price of the file being the store. The reload's read
  and digest of 21 ms per feed stays, because that is the honest test.

- **71c. Three of four zone rebuilds never got #61b's `reserve` — filed and
  closed 2026-09-16.** **793 ms to 445** for `ixfr::Patch::apply` at a million
  records, and the fix is one line at each. Found while sizing 71a, which is the
  point of the row: 71a was filed as a type problem and over half of its number
  was a missing capacity hint.

  `Zone::new` starts with an empty `HashMap`, so a rebuild grows the index by
  doubling and rehashes every key already in it at each step — and for a feed
  of `<name>.<origin>` rules the index reaches **two** entries per record, one
  for the owner and one for the empty non-terminal above it (#61's own
  measurement). **#61b built `Zone::reserve` for exactly this** and wired one
  caller, `zone/parse.rs`. Four call sites build a zone record by record; the
  other three all knew their counts and none of them passed them:

  | site | what it rebuilds | before | after |
  |---|---|---|---|
  | `ixfr::Patch::apply` | a delta onto the base | 793 ms | **445 ms** |
  | `xfr::AxfrAccumulator::into_zone` | a whole transfer | 1 450 ms | **1 134 ms** |
  | `update::Applied::into_zone` | an UPDATE's result | 381 ms | **302 ms** |
  | `zone/parse.rs` | a zone file | — | done by #61b |

  Each is an A/B on the committed harness with the one line reverted and
  restored, not a before-and-after of the tree.

  **`reserve_like` and not `reserve` at the three**, because a caller holding
  the base knows both counts where #61b's caller could only estimate one from
  the other. 61b's hint is `2 * records`, which is right for a feed of rules and
  "one doubling of the table too many for a zone whose names are all children of
  the apex" — its own words. The exact form measured 15 ms better at a million
  records and, more to the point, sizes the table right for every zone shape.
  The UPDATE site is the flat zone 61b warned about, which is why its saving is
  the smallest of the three.

  **The signer was tried and is declined on the measurement.**
  `zone_signer::sign_zone_inner` builds a `Zone` from a base the same way, so it
  looked like a fifth site. A signed million-record load is 27.5-28.2 s with the
  reserve and 27.2-27.9 s without — the path is ECDSA-bound and a ~350 ms index
  saving is 1.3% of it, which is under what the only harness that reaches it
  (`reload_cost_against_zone_size`) can resolve. Reverted rather than landed
  under a comment claiming a benefit nothing showed (§4). If #65 ever gets a
  harness that isolates that zone build, this is one line.

  **What this says about #61b, and it is not that it was wrong**: the
  measurement was right and the fix was right, and it reached one of four
  instances. §18 asks for the count *before* fixing one, and this is the shape
  that rule exists for — a `grep` for `Zone::new` would have found all four the
  day 61b landed.
---

### 72. A zone's arena is filled from something the caller already allocated — **filed and closed 2026-09-19**, seven allocations a record to none

Out of 71e, whose measurement said the load path would not move and was right
about why: a zone keeps its owner names and its RDATA in two arenas now, but
`Zone::add_record` takes an owned `ZoneRecord`, so building a zone record by
record costs the caller's two allocations *and* a copy into the arena.

**227 ns a record to 277** on the "built, not parsed" line of
`rdns/tests/scale.rs` at a million records — 50 ms a million, against the 79 ms
a million every *copy* of that zone stops paying (#71e). A parse does not show
it: 599.8 ms before and 588.8 after, 8 000 062 allocations and 8 000 065,
~~because the parse is dominated by the eight allocations a record already costs
it.~~

**The count was right and it pointed the wrong way** (2026-09-19). Seven
allocations a record on the load line of `rdns/tests/scale.rs` — a different
input from 71e's million-*rule* RPZ figure above, which is why the two counts
differ — and the two this row names are the two smallest:

| | what | per record |
|---|---|---|
| 96 B | `tokenize`'s `Vec<Cow<str>>`, one per line | 1.00 |
| 64 B | `parts: Vec<&str>` — a second copy of that same list | 1.00 |
| 24 B | the owner `Name` from `name_at` | 1.00 |
| 24 B | `state.owner = Some(name.clone())` | 1.00 |
| 24 B | **`Zone::add_record`'s own index key**, which this row did not count | 1.00 |
| 4 B | the `RecordData` box | 1.00 |
| 1 B | `parts[idx].to_uppercase()` | 1.00 |

Five came out without touching how an RDATA is built. Cumulative, on the load
line of `rdns/tests/scale.rs` at a million records, Windows release:

| | ns/rec | allocs |
|---|---|---|
| as filed | **480** | 7 |
| fold the index key onto the stack (`NameRef::folded_into`) | 432 | 6 |
| refill the token vector per line instead of rebuilding it | 419 | 5 |
| `Zone::add(ZoneRecordRef)`, owner carried as octets not cloned | 380 | 4 |
| upper-case the type name on the stack | 348 | 3 |
| `Name::absolutized_in` — this row's name half | **322** | 2 |

An alloc-and-free pair is **~32 ns** for the small ones and **~13 ns** for the
two per-line `Vec`s: it is the count that costs, not the octets. `Zone::clone`
is unchanged at 30.6 ns and `parse an eight-record zone` is 91 allocations to
54, the 54 read on Windows and on Linux (`rdns/tests/allocations.rs`).

**The row's own headline was not the copy.** "Built, not parsed" reads 257 ns
to **211** from the index-key fold alone — 46 of the 50 ns this row was filed
at, from one line in the same function, and the copy is still there.

~~**No remedy claimed, and the obvious one is not it.** A borrowed
`Zone::add(NameRef, Ttl, Class, RecordDataRef)` saves the copy and not the
allocation~~ — right about the parser as it stood, wrong about the order.
`Zone::add` is the *prerequisite*: it is what lets the owner name live in the
parser's own buffer rather than in a `Name`, which is what removes both 24-octet
name allocations. On its own it takes a zone-to-zone copy from 229 ns and two
allocations to 146 and none. The rest of the paragraph stands — what removes the
last of it is a parser that writes straight into the arena, and `Name`'s
invariant survived it because `Name::absolutized_in` hands back a `NameRef` and
`presentation_wire_in` was already the no-allocation primitive underneath
`Name::relative_to` (`CLAUDE.md` §17). `Name::absolutized_in` would have been a
second copy of `zone::parse::absolutize`'s three spellings of an owner name —
`@`, a trailing dot, everything else — so `absolutize` delegates to it and the
rule is still written once (§7).

~~The three other build sites are `xfr::AxfrAccumulator::into_zone`,
`update::Applied::into_zone` and `ixfr::Patch::apply`'s appends, and each has
the same shape (§18: count the instances before fixing one).~~ **Counted, and
none of them gains from the borrowed door** (§19): all three consume owned
`ResourceRecord`s that the *message* parser already allocated, so
`Zone::add(rr.as_ref())` still drops them — the same argument this row makes
about the zone parser, one layer out. And the site with the most calls is the
one to leave alone: the signer's seven `add_record`s add an RRSIG per RRset and
an NSEC per name at **~27 µs a record** (#44c's full sign, 26.9–27.3 s in #64d),
so 30 ns is 0.1% of it. One `grep` and one table, neither taken when the row was
filed.

The zone-to-zone `to_owned()` shape the borrowed door is worth most to has **no
production call site**: `rdnsd/src/zones.rs` and `rdnsd/src/main.rs` have one
each, both under `#[cfg(test)]` and both cloning twice, and `Zone::rebuild`
already goes arena to arena.

#### 72a and 72b, and the last allocation — **both closed 2026-09-19**

- **72a. `rdata_from_fields` took the same field list twice**, `fields: &[&str]`
  beside `text_fields: &[Cow<str>]`, which is why `parts` could not be refilled
  per line the way `tokens` is — it borrowed `tokens`. Filed as §7's shape and
  worth ~13 ns; what it actually was is §4's, and one `let` settled it: `parts`
  is `tokens.iter().map(Cow::as_ref).collect()`, so the two are the same
  strings by construction, and the doc comment saying one kept its quotes was
  wrong about both — `tokenize` consumes a quote, never pushes it.
  One list now. `rdns_present::svcb::parse_params` takes `S: AsRef<str>`
  rather than the parser's token type, which is the one thing the other crate
  should not have to know.
- **72b. The RDATA half**, and it went to **zero allocations a record**, not to
  the one the row predicted. `rdata_from_fields` hands back a `ParsedRecord`
  and `Zone::add_parsed` encodes it into the zone's own arena through
  `RdataArena::push_parsed` — a door as trustworthy as
  `RecordData::from_parsed`, which also takes its TYPE and its octets from one
  `ParsedRecord` and checks neither, because `encode` is `decode`'s inverse.
  What neither door allows is a TYPE paired with octets of the caller's
  choosing (§17). `ParsedRecord::encode` is now a wrapper over `encode_into`,
  its 16 arms appending rather than each building a `Vec`. A failed encode
  truncates the arena back, so a refused record leaves nothing behind.

  The three doors — `add_record`, `add` and `add_parsed` — are one filing path
  with three ways in, and `chain_key` stopped taking a whole record for the two
  fields it reads.

**On `rdns/tests/scale.rs`'s zone at a million records.** The last two rows are
one session minutes apart, which is the pair that prices this change; the first
is the figure the row was filed at, and 332 is what the same tree reads today,
so the box is a few per cent slower than it was and the *allocation* counts are
what to compare across the whole table:

| | ns/rec | allocs |
|---|---|---|
| as #72 was filed | 480 | 7 |
| after #72's first pass, then | 322 | 2 |
| **after #72's first pass, today** | **332** | 2 |
| after 72a | — | 1 |
| **after 72a and 72b** | **~263** | **0** |

A zone of A records now parses with **no heap allocation per record at all**:
what is left is the arenas growing. A mixed zone — A, AAAA, CNAME, MX and TXT
in equal parts — is 535 ns and 6.38 allocations to **438 and 3.58**, and the
remainder is `ParsedRecord`'s own owned fields, which is where 72b said the
ratio would live. `parse an eight-record zone` is 91 allocations to **34**,
reading the same on Windows and on Linux.

**The measurement that nearly went the other way** (§10, §19). 72b's first
version moved an *exact* count **up**: `parse a response with compressed names`
15 to 18, one per record, on the message path — which is per query where the
zone parse is per load. The cause was not the design but `Vec`: growing one from
empty takes a byte vector's capacity to 8 whatever it holds, where the arms'
old `to_vec()` sized exactly, so `into_boxed_slice` then had to reallocate to
shrink. `RecordData::from_wire` sizes its buffer from the RDLENGTH
that arrived — re-encoding changes the length only where a compression pointer
was expanded, and then upwards — and the count is 15 again. Had the range been
a floor rather than an exact number, this would have shipped.

**What is deliberately left.** The signer has seven `add_record` sites, all fed
by `RecordData::from_parsed`, and two of them scale with the zone: an NSEC per
name and an RRSIG per RRset. They are 72b's shape exactly and they stay, for
the reason measured above: signing is ~27 µs a record, so an allocation is
0.1% of it. `xfr`, `update` and `ixfr` hold a `RecordData` that the message
parser already built, so `add_parsed` has nothing to offer them either.

---

### 78. `rdnsr`'s query path loses work at three of its exits — **filed 2026-09-19, closed 2026-09-20**

`handle_query` is 420 lines with 15 exits and a tail that does five things.
Three of the exits skip something the tail does. The first was verified here by
reading every exit; b and c were the review's reading, and both were
re-checked against the code before being touched — both held.

- **78a. A prefetch is discarded by `.into()`.** `refresh` is set at
  `answer.rs:422` when the answer cache says the entry is in the last tenth of
  its TTL. `impl From<Option<Vec<u8>>> for Answered` fills `refresh: None`, and
  the `on_answer` exit at `:599` is `return reply.into()`. So an `rpz-ip` rule
  matching a cache-hit answer silently disables prefetch for that name: the
  entry ages out, the next client pays a full recursion, and nothing counts it.

  **Exactly one live exit, not three.** The other two `.into()`s that follow
  `:422` in the file (`:496`, `:544`) are inside the cache-*miss* arm, where
  `refresh` cannot have been set. Counted before proposing anything (§18).

  One line fixes it. The type-level version — delete the `From` and let the
  compiler enumerate all 15 exits, or hand `&mut Option<QuerySection>` in from
  the socket loop so the value never travels through a return at all — is the
  §17 shape and is ~15 sites. **Build both before choosing**; the second makes
  the whole class unrepresentable and the first only makes it visible.

  **Closed 2026-09-20. Three shapes built** (§19), and the one that shipped is
  in neither of the two the row named.

  Provoked first: `a_rewritten_answer_still_asks_for_its_refresh` puts an
  `rpz-ip` rule over a cache entry 95 seconds into its 100-second TTL and
  reads `refresh` — `None` against `Some("hot.example.com.")`.

  | | A1: one line | A2: delete the `From` | B: `&mut Option<QuerySection>` |
  |---|---|---|---|
  | diff | 1 line | 128/40, one file | 158/103, three files |
  | sites the compiler names | 0 | **14**, not 15 | 68 errors over ~35 call sites |
  | after it | the class can recur silently | recurs visibly: a new exit spells `refresh: None` | — |
  | surprises | — | clippy's `redundant_field_names` ×3 | the local `refresh` shadows `fn refresh`, so two sites need `crate::answer::refresh`; `Answered`'s doc comment, which holds §9's reason the prefetch is handed back rather than spawned, has nowhere to live; clippy then wants `?` where `let…else` was |

  **B's claim does not survive being built.** It does not make the class
  unrepresentable, it moves it to the call site: a caller may pass `&mut None`
  and ignore it, and the mechanical conversion wrote exactly that at **32 test
  call sites** — the silent drop, spelled out 32 times, as the idiom the next
  test copies. It also deletes the type whose doc comment is the reasoning.

  **What shipped is C, which neither the row nor the review considered: delete
  the early return.** The hazard is §7's "an early `return` that jumps over a
  shared epilogue", so the fix is to stop having two exits — the `rpz-ip`
  block yields `Option<Option<Vec<u8>>>` and the tail chooses between it and
  `finish_dns64`. 85/9 in one file, one exit after the set point, and the
  comment says why there is no `return` there. A2 is then 128 lines to restate
  `refresh: None` at 13 exits that are all *upstream* of the set point, where
  the compiler can already prove it.

  One behaviour change, pinned by a second test: `rpz-drop` keeps its prefetch
  now, where before it took the same lossy exit. Refreshing a dropped name is
  how it stops being blocked when it moves off the address the rule names.

  The patches for A2 and B are not kept as branches — both are mechanical from
  this description, and the numbers above are what they were built for.
  Measured: `rdnsr`'s cached answer still costs **13 allocations**, first and
  201st; 1 260 tests on Windows and 1 281 on Linux.

- **78b. Forward mode returns the upstream's header verbatim.** ~~The
  review's reading, not re-checked.~~ **Verified and closed 2026-09-20**, and
  both consequences were live. `recurse.rs` normalized a recursed answer —
  `response.queries = vec![query.clone()]` and `authoritive = false` — and
  `Resolver::forward` did not; `handle_query` sets `id`, `response`,
  `recursion` and `recursion_ok`, and `finish` always sets `ad`, so AA and the
  question were the two nobody owned.

  Provoked before fixing (§1, §4): a fake upstream that answers
  authoritatively and echoes the question as it arrived — what a real server
  does — made `resolve` hand back AA=1 and the question `EXaMple.COm.` for a
  client that asked `example.com.`. The case matters more than it looks: a
  downstream resolver running its own 0x20 compares the echoed question
  **case-sensitively** (RFC 5452 §9.1), and this crate's `response_matches` is
  that check — so an `rdnsr` in front of an `rdnsr` would have rejected the
  answer. AA=1 is the RFC 8020 hazard §8 already names, on a resolver that is
  authoritative for nothing (RFC 1035 §4.1.1).

  Fixed where the row said, in `resolve_validated` past the mode match, and
  `recurse`'s two lines are gone rather than left as a second copy (§7). One
  production site sets AA on this path now, and a `QuerySection` compares
  case-insensitively (RFC 4343), so the test asserts on the text — the
  assertion a `==` would have passed.

  **Left behind: #93**, the same scramble in the answer records' *owner*
  names, which is data rather than a header and is not the same fix.

- **78c. QDCOUNT=0 is dropped here and answered by `rdnsd`.** ~~The review's
  reading, not re-checked.~~ **Verified and closed 2026-09-20**, and both
  halves were live: `rdnsr`'s `handle_query` bailed with `return None.into()`
  on `queries.first()`, `rdnsd`'s `make_response` fell past its
  `queries.len() > 1` check into the tail and answered an empty NOERROR. One
  packet, two daemons, two behaviours, and only one of them wrote down why.

  **The RFC does not settle it**, as the row said: §4's only sentence about
  QDCOUNT = 0 is "Such firewalls MUST NOT treat messages with OPCODE = 0 and
  QDCOUNT = 0 as malformed" — addressed to middleboxes deciding what to
  forward, not to responders deciding what to answer. `rdnsd`'s comment and its
  test had read it as the second, which is how an empty NOERROR came to be
  asserted.

  **What settles it is RFC 7873 §5.4**, which is the only place that says what
  such a query is *for*: a cookie probe. It extends the QUERY opcode to an
  empty question section "for servers with DNS Cookies enabled" — neither
  daemon is, `EDNS_OPTION_COOKIE` is a constant and nothing implements the
  option — and ends "servers that don't support the COOKIE option will
  normally send FORMERR in response to such a query, though REFUSED, NOTIMP,
  and NOERROR without a COOKIE option are also possible". So `rdnsd`'s NOERROR
  was permitted and `rdnsr`'s drop was not on the list at all.

  **So the peers were asked** (43e's QDCOUNT = 0 block, which dig cannot send):

  | | no OPT | OPT, no COOKIE | OPT + COOKIE |
  |---|---|---|---|
  | BIND 9.20.27 | FORMERR | FORMERR | NOERROR + cookie |
  | Knot 3.6.0 | FORMERR | FORMERR | FORMERR |
  | NSD 4.12.0 | FORMERR | NOERROR | NOERROR |
  | Unbound 1.23.1 | FORMERR | FORMERR | FORMERR + cookie |

  **All four answer; none drops.** That is the finding, and it is the
  measurement that could have refuted it (§19): one peer dropping would have
  made `rdnsr`'s behaviour the majority rather than the outlier. FORMERR is
  unanimous for the probe with no OPT, and NSD's NOERROR is §5.4's extension
  relaxed from "an OPT with a COOKIE" to "an OPT" — a reading available only to
  a server that implements cookies. Both daemons answer FORMERR now, at both
  question counts, which is one `match msg.queries.as_slice()` in `rdnsd` and
  one `let [query] = … else` in `rdnsr`, placed after the EDNS-level
  rejections so the two agree on which error wins.

  **A second defect the probe found and the review did not**: `rdnsd` set
  **AA** on that NOERROR. `w.set_authoritative(true)` is the first line of
  `write_response` and only the branches that decide otherwise clear it, so the
  one reply with no question section carried a claim of authority over no name
  (RFC 1035 §4.1.1, "the responding name server is an authority for the domain
  name in question section"). No peer sets it. `CLAUDE.md` §7's
  `truncated_reply` bullet is the same shape.

  Left as it was: `rdnsr` is not in the interop network, so the peer comparison
  covers `rdnsd` and the resolver's half is three unit tests — two new, watched
  failing against the old code (`None`, and no OPT mirrored), and #30r's
  two-question one, which the restructure re-routed. `unsupported_opcode` is
  now a call to `empty_error`, since "an empty reply that mirrors the client's
  OPT" was about to be written twice (§7). Measured: 1 262 tests on Windows and
  1 283 on Linux, clippy and `cargo doc` clean on both; 43e 35 passed 0 failed.

---

### 79. Claims and code that outlived each other — **filed 2026-09-19, closed 2026-09-20**

§4's failure mode has shifted here. The old one was "the claim was never true";
these are claims that *were* true and whose subject moved. Nothing fails when
they diverge, which is the whole of §18's "dead code is a finding".

- **79a. Four `pub fn` with no caller, and an unreachable error variant.**
  Verified here: `Name::relative_to`, `dnssec::canonical_name_of`,
  `Nat64Prefix::bits` and `TransferError::refused` are named nowhere but their
  own definitions. The last is the only constructor of
  `TransferError::Refused`, so that variant is unreachable and nothing matches
  on it either.

  `relative_to` is the one that costs a reader: its doc says "the join below is
  the only allocation: **this is the zone parser's per-record cost**", the zone
  parser stopped calling it at `33461d3` (#72), and the replacement
  `Name::absolutized_in` sits eight lines below with a comment explaining that
  the allocation is gone. Two adjacent doc comments, contradicting each other,
  and the dead one comes first.

  `canonical_name_of`'s doc calls it "the boundary between a record's name and
  DNSSEC's own bookkeeping" and "the property a name refactor must not quietly
  change (#13e)". That sentence is still worth something; move it onto
  `canonical_name`, which is the live one, rather than deleting it with the
  function. §18: file, then delete.

  **Closed 2026-09-20, and the count was four because the method has false
  negatives.** Swept first (§18): of **713 `pub fn` definitions** in the
  workspace, a script matching call-shaped uses outside comments flags four —
  the two named above plus **`Class::is_meta` and `Rtype::is_meta`**, which the
  review missed. It does *not* flag `Nat64Prefix::bits` or
  `TransferError::refused`, which are dead too: a string literal carrying the
  word "bits", and `rdnsd`'s unrelated `.refused` struct field, are enough to
  hide them. So the tree had **six**, the sweep finds four, and a name-based
  sweep cannot do better — #82b's point about #38's criterion having no
  compiler behind it, arriving from the other side.

  Two of the six were not dead code at all, which is why "delete it" was the
  wrong reflex twice:

  - **`Rtype::is_meta` is the reasoned copy of a live predicate.** RFC 2136
    §3.4.1's prescan in `update.rs` spells `rtype == rt::ANY || rtype ==
    rt::AXFR || rtype == rt::IXFR` by hand, and `is_meta` is that expression
    with the RFC citation on it (§7). Wired in; its doc's claim that the
    prescan refuses an UPDATE adding one is true by reference now rather than
    by coincidence.
  - **`TransferError::Refused` was unreachable because the site that should
    build it builds `Malformed`.** A master answering REFUSED comes back as
    `TransferError::malformed("master answered Refused")`, under a variant
    documented as "the transfer arrived but does not assemble into a zone".
    ~~Deleted anyway, per §3's "a variant nobody matches on is a `String` with
    extra syntax", and `Malformed`'s doc now covers the case it has always
    carried. What decided it: **nothing branches on any `TransferError`
    variant** — every transfer failure reaches one `warn!` and the same RETRY
    timer in `replication.rs`.~~ That is **#95**, **and the deletion was right
    for a reason that was not checked** (2026-09-20). "Nothing branches" was a
    measurement of the tree, not of the problem: #95's survey found that a
    caller *should* branch here and does not, which is **#96**. The variant is
    back as `Rcode(ResponseCode)` — the reasoning that deleted it is why it came
    back in a better shape, since a variant named `Refused` still could not have
    carried the other codes. What the row should have asked, and §19 now says
    to: not "does anything match on it" but "would anything match on it if it
    were right".

  Deleted: `Name::relative_to` (with its stale "the zone parser's per-record
  cost", whose replacement sits eight lines below saying the allocation is
  gone), `canonical_name_of` (sentence moved onto `canonical_name`, where it is
  about the live function), `Nat64Prefix::bits`, `Class::is_meta` (whose
  predicate the UPDATE path expresses as `QueryClass::Any | QueryClass::None`,
  and whose stronger guard is the zone parser refusing a non-IN record at all)
  and `TransferError::refused`.

- **79b. `CLAUDE.md` §17's list is five-sevenths stale — closed 2026-09-20.**
  It opened "The smells, all currently in this tree" and pointed at
  "`TODO.md` §13", which closed on 2026-08-02 and now lives in
  `docs/CLOSED_WORK.md`. Measured here: `num_derive` is gone from the workspace
  entirely (one comment in `deny.toml` survives it) and no wire-field parse
  uses `unwrap_or`. The review's own table makes it five of the seven — OPT
  out of the record list, the QTYPE/RTYPE and QCLASS/CLASS newtypes, `Serial`
  without `PartialOrd`, the TTL clamp and `num_derive` — leaving only "the same
  normalization per module" and "an invariant asserted in a doc comment" live.
  **Re-measure each of the seven before editing the section**, then correct it
  in place with the reasoning kept (§11: it is a claim, not a status line).

  **Re-measured, all seven, and the verdict holds with its itemization
  corrected.** Five are fixed and two are live, and the two live ones are the
  two the row named. What the row got wrong is *which* five: it counted "the
  TTL clamp" as a sixth item when the clamp is the OPT bullet's own
  consequence, and it left out the seventh bullet, "a `pub` field beside a
  checking constructor", which #14 closed when it sealed `RecordData`. Five
  names, four bullets, one missed — the arithmetic worked out only because the
  two errors cancelled.

  | §17 bullet | today |
  |---|---|
  | OPT's CLASS and TTL mean two things | **fixed** #13a-#13d: `DnsMessage::edns` is an `Option<Edns>` field, and `Ttl::from_wire` is the only place the wire field's sign is read. Four `.max(0)` left in the tree, none a TTL, against "fourteen times" |
  | a QTYPE is not an RTYPE | **fixed** #13a-#13d: `Qtype`, `Rtype`, `Class`, `QueryClass` |
  | a serial's ordering is not the numbers' | **done** #14: no `PartialOrd`, 21 callers of `is_newer_than`, one arithmetical comparison at `zone_signer.rs:2332` with its reason |
  | `unwrap_or` on a wire field, and `num_derive` | **fixed** #13a-#13d: no `num_derive` in the workspace, no such `unwrap_or` |
  | the same normalization per module | **live**: #81b |
  | an invariant asserted in a doc comment | **live**: #79d, #79e, #79f |
  | a `pub` field beside a checking constructor | **fixed** #14: `RecordData` and `RecordDataRef` hold private fields — and #82b put a compiler behind the neighbouring shape |

  Two claims in the opening paragraph went with them, and they are kept rather
  than struck, because that paragraph *is* the controlled experiment §17 argues
  from: "the ASCII case fold exists in nine places including one in the public
  API doing the Unicode fold" is now no `to_lowercase` on a name anywhere, with
  `Name`'s own `PartialEq` and `Hash` folding ASCII. The section says so in a
  dated note beneath it.

- **79c. `rdns/src/lib.rs:62` documents the wrong module.** "Scratch
  directories, for tests only." sits above `pub mod tls_identity;`. It
  documented `mod testutil;` until #66c moved that module out from under it.
  `cargo doc` cannot catch this — it resolves, it is simply false — and it
  renders as `tls_identity`'s summary on the crate page. One line.

  **Closed 2026-09-20 as #89**, `73d34c9`, which is this row filed a second
  time the following day by a review that did not read this one. Two numbers
  for one defect is what a queue with rows nobody re-reads produces; the cost
  was small here because #89 took the same line out, and it is the argument for
  §18's "count the instances" being a `grep` over the *page* as well as over
  the tree.

- **79d. `ede.rs`'s module header names the wrong guarantor.** It says
  "`ClientEdns::mirror` is the only way to a reply's OPT … so an EDE with no
  OPT to ride in is not expressible (§17)". `ResponseWriter::set_edns` is
  `pub` and is used without `mirror` at five sites. The *conclusion* still
  holds, by `ResponseWriter::finish`'s `if let Some(mut edns) = self.edns.take()`
  — and `set_extended_error`'s own doc states it correctly. So the codebase has
  the right claim in one file and a wrong mechanism for it in another. Cite the
  guard; a test that sets an EDE with no OPT and asserts nothing reaches the
  wire would make it a fact rather than a citation.

  **Closed 2026-09-20**, both halves. Three of `rdnsd`'s answer paths call
  `ResponseWriter::set_edns` without `mirror` (`answer.rs:66`, `:90`, `:121`),
  so §17's "not expressible" was never a property of the type. The header
  cites `finish`'s guard now and strikes the old mechanism rather than
  overwriting it (§11), and `an_extended_error_with_no_opt_reaches_no_wire` in
  `response.rs` asserts the conclusion: no OPT, so no EDE and no option code 15
  anywhere in the bytes. Checked by loosening the guard to synthesize an OPT
  — the test fails (§1).

- **79e. `dnssec_answer.rs:200` holds on four of six paths.** It says
  `*.<closest encloser>` is "guaranteed absent by `Zone::name_kind`". Of
  `name_kind_of_key`'s six `NotFound` returns, four establish it, one is
  vacuous, and the delegation one (`zone.rs:1246`) does not — it returns
  `NotFound` because RFC 4592 §2.2.1 forbids synthesis below a cut, which says
  nothing about the index. The invariant appears to hold anyway, via
  `resolve_in_zone` answering a referral first, so the remedy is a sentence
  naming the real guarantor and **not** a check. Confirm with a zone that has a
  delegation at `sub.` and a wildcard at `*.sub.` before writing it.

  **Confirmed and closed 2026-09-20.** That zone is
  `a_wildcard_below_a_cut_is_still_a_referral` in `rdnsd/src/answer.rs`: with
  `*.sub IN A` beside the `sub` delegation, `nothing.sub.example.com.` comes
  back a referral — NOERROR, AA clear, the child's NS RRset, no denial record
  — because `resolve_in_zone` asks `delegation_for` before anything else,
  which is RFC 1034 §4.3.2's first case and `CLAUDE.md` §8's first bullet. The
  sentence in `dnssec_answer.rs` names that caller now.

  One correction to the row's own count: by my reading **three** of the six
  `NotFound` returns establish the invariant, not four — no wildcards in the
  zone (`zone.rs:1243`), a wildcard that would break 255 octets (`:1251`), and
  the index saying it is absent (`:1256`). **Two** are vacuous, not one: out of
  the zone (`:1234`) and the loop ending with no encloser found (`:1259`),
  which an in-zone name cannot reach because the apex always exists. The
  delegation one (`:1246`) is the one that does not, which is the row's point
  and is right.

  Worth naming: the precondition is in `rdns` and the guarantor in `rdnsd`, so
  the test has to live in the other crate, and does.

- **79f. Two config claims about where a rule is enforced.**
  `rdns/src/config.rs`'s macro says a listener with no certificate "is refused
  by each daemon's `check`" — true of `rdnsr`, false of `rdnsd`, which refuses
  it in `main`. And `rdnsd/src/config.rs`'s header names the flags exempt from
  `--config` as three where clap has six. Both are three-line corrections; the
  first has the option of making the claim true instead, which would also give
  a config-file user a line number.

  **Closed 2026-09-20, and both counts held.** Of `Cli`'s **46 `#[arg]` fields,
  40 carry `conflicts_with = "config"`**; the exempt six are `--config`,
  `--check-config`, `--generate-keys`, `--key-algorithm` (that one's
  parameter), `--log-level` and `--quiet` (which the file has no key for). The
  header names all six and points at the attribute as the authority.

  **The option of making the other claim true was declined, with the reason
  written in.** `rdnsd` refuses a listener with no certificate in `main`, where
  the flags and the file have already merged into one `Cli` and the store is
  about to be loaded; moving it into `Config::check` would add a *second* check
  rather than move one, because the flag path still needs it and clap's
  `requires` cannot express "either listener needs the pair". The cost is a
  file error without a line number, and the dry run reaches the check anyway
  — it is at `main.rs:2053` and `--check-config` returns at `:2292`.

---

### 80. Two bools where the enum is already imported — **filed 2026-09-19, closed 2026-09-20**

`dnssec_validation_mode::validate_rrset` returns `(bool, bool)`, documented as
`(is_valid, is_signed)` in prose and nowhere in the type. Seven bare tuple
literals inside the file. **All four call sites discard the second element**,
because each already holds the `ZoneKeys` that answers it — so the bool is
redundant by construction rather than by accident. `validate_response` beside it
has zero callers and carries an unused `_query_name` in a public signature.

The function converts an `RrsetProof` — a four-variant enum imported at line 8
of the same file — into two bools, one of which nobody reads.

§17's own controlled experiment is the argument: the two defects fixed by
changing a type have not recurred and every one fixed at a call site has. Return
the proof, or a three-variant verdict; delete `validate_response`. ~30 lines,
four call sites.

**The refuting check**: a caller that needs `is_signed` *without* already
holding the keys. The review found none; confirm it, because if one exists the
remedy is naming the fields rather than collapsing them.

**Confirmed, and there is none.** Two production call sites, both in
`zones::verify_zones`, both `let (ok, _)`, and the first calls
`keys.is_signed()` on the line above the call that returns it again. The row's
"four call sites" counted the two tests with them, which is right about the
shape and worth spelling out: `scale.rs` and `allocations.rs` discard it too.
Correction to the row: `validate_response` had **one** caller, a test in its
own module, not zero.

**Closed.** `validate_rrset` returns `Verdict::{Unchecked, Valid, Invalid}`,
the three-variant shape the row named. `Invalid` carries the sentence, which
the pair could not: `verify_zones`'s error was "does not verify against the
zone's own keys" for an expiry, a missing signature and an unreadable
algorithm alike, and now names which. The seven tuple literals are gone with
it, and every test asserts on the variant (§3).

Deleted with it, both dead and both #79a's shape found in this module:
`validate_response` (its only caller a test, and an unused `_query_name` in a
public signature) and `is_zone_signed` (its only callers its own two tests,
and a second spelling of `ZoneKeys::of(...).is_signed()`). Five doc comments
in four files named `validate_response` while telling #50's story; each now
describes the old shape rather than the gone name, which is #89 avoided in
advance.

**One test caught in the act** (§1). The first version of the "no usable key"
test built a DNSKEY with protocol 4 and asserted `!is_valid()`, which passed
— for the wrong reason. Pinning the message showed the verdict was "no
signature covers it": `Dnskey::from_record` does not look at the protocol
field at all. The test became the reachable case, and the protocol field is
**#94**.

Measured: `cargo test -p rdns --test allocations` reads 33 either side, and
1 256 tests on Windows against 1 256 before (two tests added, two deleted),
1 277 on Linux.

---

### 81. What #63h's macro did not reach, and one more copy — **filed 2026-09-19, closed 2026-09-20**

- **81a. The `[keys]` TSIG table is declared twice — measured and mostly
  declined, 2026-09-20.** #63h put the 22 shared `[server]` keys in
  `rdns::server_table!` and `[keys]` was not in its scope: two `Key` structs,
  two default-algorithm functions with different names and the same value, two
  validators that differ only in a brace, and **two hardcoded copies of the
  algorithm list in the error text** — the one that can go stale in silence,
  since nothing compared either to `TsigAlgorithm::from_name`.

  **#63h's measurement, taken.** Of the 27 commits that have touched
  `rdnsd/src/config.rs`, **8 touch its TSIG lines, and 1 of those 8 also
  touches `rdnsr`'s** — `64b34d2`, which is the commit that *created*
  `rdnsr`'s copy rather than an edit to two. Against `[server]`'s 12 of 23,
  that is the refutation the row asked for: **they do not co-move**, so the
  shared struct is declined.

  **And a second one the row did not engage** (§19: answer the reason the code
  states). The two tables are not the same table. `rdnsd`'s `Key` has `zones`
  and `update-zones`; `rdnsr`'s carries a header saying why a resolver has
  neither — "a resolver *fetches*, so it authenticates the master and
  authorizes nothing". Three fields of five are shared, not five.

  **What was taken**, which is the list and the default under it:
  `TsigAlgorithm::ALL`, `::ACCEPTED_NAMES` and `::DEFAULT` in `rdns-tsig`, with
  `::config_name()` for the spelling without the wire's dot. Both config
  parsers print the shared list, and so does `TsigKey::parse`, which **had no
  list at all** and said only `unknown TSIG algorithm "md5"` — so the flag path
  came out better than it went in. `accepted_names_are_the_ones_parsed` checks
  both directions: every listed name parses, and every variant is listed. The
  two `default_*_algorithm` functions stay, three lines each, but they now read
  the value from `TsigAlgorithm::DEFAULT` rather than holding a third and
  fourth copy of `hmac-sha256` — the flag's default and the file's default are
  one decision.

- **81b. FNV-1a over ASCII-folded bytes, twice — closed 2026-09-20.**
  `compression::folded_hash` and the loop inside `zone_signer::expiry_for`, same
  offset, same prime, same fold, each with its own comment stating the same
  requirement in different words. The asymmetry is what a drift would cost: one
  loses a compression pointer, the other moves every RRSIG expiry in every zone
  at once, and §8 requires that two servers holding the zone agree about it.

  **They agreed**, and the row's own instruction is how that was established
  rather than assumed. The check is not an assertion that the two loops compute
  the same number — that would be a test of a copy — but a golden test taken
  *through the observable*: six `expiry_for` offsets measured against the tree
  before the merge, asserted after it. Unchanged, so the merge moved no
  signature's expiry.

  `rdns_core::folded_hash`, one function over a byte iterator, because the two
  callers hash different things — the compressor a suffix, the signer a name
  plus two octets of type — and two entry points is what invites the next copy.
  The module doc carries the asymmetry, which is the reason §7 says to move
  (the two old comments each stated half of it). `expiry_for`'s note about
  `DefaultHasher` being per-process seeded went with it: that is a fact about
  the hash, not about the signer.

  Golden tests on both sides: `folded_hash::the_hash_is_the_hash_it_was` pins
  the empty input and one name, and `zone_signer::the_spread_is_the_spread_it_was`
  pins the six offsets, with a note saying the number is *allowed* to change and
  that changing it deliberately means re-signing every zone — which is what
  should have to be typed out.

---

### 82. Two modules in the wrong place, and a `pub` with no ratchet — **filed 2026-09-19, closed 2026-09-20**

- **82a. `readiness` is in `rdns` and `rdns` never uses it — closed
  2026-09-20.** `grep` over `rdns/src` returns one line: the `pub mod`
  declaration. Its five consumers are `rdns-transport`'s metrics server — which
  *serves* `/readyz` — and the two daemons. One dependency,
  `rdns_core::text_names::ascii_lowered`, which `rdns-transport` already has.
  File move, five `use` edits, one `mod` line, no manifest change.

  **The estimate held to the line except one**: five `use` edits, no manifest
  change, and *two* `mod` lines, because a move is a delete and an add. The
  dependency reached through `rdns`'s `pub use rdns_core::*` rather than
  directly, which is why no manifest moved — `rdns-transport` names
  `rdns::text_names::ascii_lowered` and has no `rdns-core` of its own.

  **What it does not buy, said plainly**, because the measurement above this row
  is about exactly that: the `rdns-transport` → `rdns` edge is untouched,
  `cargo tree -p rdnsd` is 150 either way, and nothing rebuilds faster. What
  changes is that `rdns` stops publishing a module no module in it names, 34
  `pub mod` where there were 35. The module says why it lives where it does now,
  so the next reader does not have to find this row.

  This is the one piece of "the furniture is in the wrong crate" that survives
  its own refuting measurement. The larger version — an `rdns-ops` crate under
  `rdns-transport` holding `shutdown`, `metrics`, `security`, `logging`,
  `tls_identity` and `readiness` — takes **no package off any binary**
  (`cargo tree -p rdnsd` is 120 either way), which is the limit #67 wrote down.
  ~~Revive it only with a rebuild-time measurement, which nobody has taken.~~

  **Taken 2026-09-20, and it agrees: still decline.** What the
  `rdns-transport` → `rdns` edge costs is one crate's rebuild whenever `rdns`
  changes, and `rdns-transport` does not name the module that changed. Windows,
  warm `target/`, `cargo build --workspace`: no-op 160 ms; touching
  `rdns/src/zone.rs` rebuilds `rdns`, `rdns-transport`, `rdnsd`, `rdnsr` at
  **3 271-3 437 ms**; touching `rdns-transport/src/tcp.rs` (transport plus both
  binaries) 2 766-2 826 ms; touching both binaries alone 2 244-2 392 ms. So the
  transport link is **~450 ms of a ~3.3 s rebuild, 14%** — and that is the
  ceiling, not the saving, because the binaries still depend on both crates and
  a split only lets them start on `rdns`'s metadata sooner. Not worth six
  modules and a manifest. 82a's own move stands on the measurement above it.

- **82b. Five `pub fn` on private structs in `xfr.rs`, and the ratchet question
  behind them — closed 2026-09-20.** `AxfrAssembler` and `IxfrAssembler` are
  private and their `new`/`accept`/`into_zone` were `pub` — #38's exact shape,
  in a module #38 swept. They are module-private now, not `pub(crate)`: the
  structs they hang off cannot be named outside `xfr` either.

  **The ratchet is taken.** `RUSTFLAGS="-W unreachable_pub" cargo check
  --workspace --all-targets` gave **44 warning lines over 43 distinct sites**
  — the 44th is `xfr.rs:104` reported once per target, which is why the row
  first read "5 real and 39 from two fixture modules" and the fixture number is
  **38**. Those 38 are `test_records` and `dnssec_test_util`, both
  `#[cfg(test)] mod`, so `pub(crate)` is what they always meant. With all 43
  fixed, `#![warn(unreachable_pub)]` is in all nine crate roots and the
  workspace is clean under it; the four binaries had nothing to fix, so the
  attribute there is only the lock.

  **What it does not buy**, written on the lint in `rdns/src/lib.rs` so the
  next reader does not over-trust it: rustc answers "is this reachable from
  outside", #38 asked "is this *named* from outside", and only the first has a
  compiler. #38's sweep still has to be re-run by hand.

  ~~`pub` in `rdns/src` has gone 517 → 651 across 77 commits since the sweep,
  with `pub(crate)` flat.~~ **The direction was right and the numbers are not
  reproducible**: no command was recorded with them, and none tried here gives
  either figure. Re-measured with the criterion written down —
  `git grep -hE "^\s*pub [a-z]" <rev> -- 'rdns/src/*.rs'`, minus comment lines
  — it is **694 at #38's filing (`2835422`), 706 at #38a's close, 889 today**,
  across 168 commits, with `pub(crate)` 17 → 21. §18's "never write a number
  you did not just read" has a corollary: write the command beside it, or the
  next person cannot re-read it.

---

### 83. `rdnsd/src/main.rs` has grown two seams — **filed 2026-09-19, closed 2026-09-20**: one taken, one declined, and the criterion needed reading before either

Not a defect, and filed so the judgement stops being carried silently.

#20's criterion is explicitly *not* line count — "subsystems that have an owner
and a lifetime … the review led with the line count and that turned out to be
the weakest part of its case" — and its closing judgement was that splitting
further was not worth doing. #38d overruled that once, on evidence, by doing the
split and counting what sealed.

Taking #20's own measurement — count what each name drags behind it — two
clusters now return "seam":

- **NOTIFY going out** (`parse_notify_peers`, `build_notify_policy`,
  `announce_zones`, `announce_transfer`, `send_notify`): one reach-back into
  `main`, and it is removable — `build_notify_policy` takes `&Cli` to read one
  field. It has an owner and a lifetime, and `replication.rs` already imports
  `crate::announce_transfer` across a module boundary.
- **The reload cluster** (`Reloading`, `ReloadTrigger`, `ReloadContext`,
  `reload_once`, `spawn_zone_maintenance`, `sleep_for`): reaches `main` for
  exactly one thing, `announce_zones`, which the first move removes.

The file's code half — everything before `#[cfg(test)]`, non-blank,
non-comment — has gone **1015 → 1584 lines since #38d/#39b measured it**, with
no seam taken. (**1597 when the split was taken**, a day later.)

**The method is #38d's**: do the split, count what seals, revert if the new
module needs more `pub(crate)` than it makes private, and write *that* number
into this row. `Cli` is **not** a candidate and moving it would be a straight
loss: ~40 fields would need `pub(crate)`, which reopens 63a's sealing sweep to
buy file length.

---

**Both splits built, 2026-09-20. NOTIFY is in `notify_out.rs`; the reload
cluster is declined on its number.**

**The criterion had to be read before it could be applied, and that is the
first thing this row found.** "More `pub(crate)` than it makes private" counts
annotations, and `main.rs` is the *crate root*, where §17 already records that
private is not private: a root-private item is visible to every module in the
crate. So the five NOTIFY items were reachable from anywhere in `rdnsd` before
the move and three of them are `pub(crate)` after it — **3 against 2 sealed, a
revert on the letter** — while what actually changed is that **2 items became
unreachable from the rest of the crate and 0 became more reachable than they
already were.** The annotations went up and the visibility went down. Taken on
the second reading, because that is what the criterion is measuring; a `git
revert` of the commit is the whole cost of disagreeing.

**The NOTIFY split, measured:**

| | |
|---|---|
| moved | `parse_notify_peers`, `build_notify_policy`, `announce_zones`, `announce_transfer`, `send_notify` — 254 lines |
| `pub(crate)` | 3 — `build_notify_policy`, `announce_zones`, `announce_transfer` |
| sealed | 2 — `parse_notify_peers`, `send_notify`, which no module outside can now name |
| newly widened | **0**, for the reason above |
| `main.rs` code half | **1597 → 1434** |
| imports freed | 8 left `main.rs`'s non-test surface: `BTreeMap`, `bind_addr_for`, `zone::Zone`, `DnsMessage`, `ResourceRecord`, `NotifyPeer`, and `notify` and `tsig` as modules — five of them to `#[cfg(test)]`, which is where the file's remaining use of them is |
| tests moved | 4 of 5 |

**The row's "one reach-back into `main`, and it is removable" was right about
the one and wrong that removing it leaves none.** `build_notify_policy` took
`&Cli` to read `cli.also_notify` and now takes `&[String]`. What that uncovered
is `absolute_name`, a one-line wrapper over `rdns::text_names::absolute` that
was invisible while the code sat in the same file. **Net reach-backs: 1 before,
1 after.** It is left as `crate::absolute_name` rather than spelled out, because
`zones.rs` reaches it the same way and a second spelling is §7's whole subject.

**And the fifth test did not move**, which is the sharper finding.
`test_a_notify_can_be_signed_and_verifies_as_a_request` needs seven of
`main.rs`'s test fixtures — `ScratchDir`, `spawn_primary`, `zone_text`,
`replication`, `MasterSpec`, `refresh_once`, `test_shutdown` — because it drives
a whole replication round and *asserts* about the NOTIFY. It is a replication
test wearing a NOTIFY test's name, and it stays where its fixtures are. The
other four are self-contained and sit beside the code now.

**The reload cluster is declined, 18 against 1.** `Reloading`, `ReloadTrigger`,
`ReloadContext`, `reload_once`, `spawn_zone_maintenance`, `sleep_for` would need
`pub(crate)` on **5 items plus 13 struct fields** — `Reloading`'s 8 and
`ReloadContext`'s 5 — because `serve` builds both as struct literals, and
`control.rs` names `ReloadTrigger`. Exactly one thing seals: `sleep_for`. Unlike
the NOTIFY count this one widens for real, since those 13 fields are private to
the root today and would have to be named from outside. **It is `Cli`'s shape at
a third of the size**, which the row had already ruled out for the same reason
without noticing the two structs beside it have it too.

**What would change the answer**, so this is a measurement and not a verdict:
give `Reloading` and `ReloadContext` constructors and the 13 fields stay
private — 5 `pub(crate)` against 1, still a loss, but a close one. That is a
different change from moving a file, and it is the one somebody should price if
this comes back.

---

### 84. `to_prometheus_format` is 337 lines of one idiom — **filed 2026-09-19, closed 2026-09-20**

Thirty hand-unrolled HELP/TYPE/value blocks, 102 `push_str`, one line of doc
that restates the function's name. The three rules that are *not* obvious — and
that `CLAUDE.md` §14 spends five bullets on — are at the bottom, past 250 lines
a reader has to scroll: omit-don't-zero for an absent gauge, `escape_label` on
an operator-supplied zone name, and seconds as the base unit.

Nothing is currently missing: all 35 counter fields are rendered, and the three
series with no `# HELP` of their own are the histogram's `_bucket`, `_count` and
`_sum`, which correctly share one. **That is the point** — the agreement between
the struct and the renderer is held by hand, and a counter added without its
block would be invisible with nothing failing.

Two things the shape hid, both verified here:

- The `# HELP dns_catalog_members` line carries **22 stray spaces** before its
  text, and three `push_str` calls in that block use embedded newlines where the
  other 99 use `\n`. Cosmetic — Prometheus takes HELP as free text — and exactly
  §12's named hazard, since rustfmt does not touch string literals. No test
  looks at a HELP line.
- `metrics.rs`'s two `if let Ok(...)` guards on the zone tables are the only
  lock-guard sites in the tree that drop output on a poisoned lock with no
  commented decision. A poisoned `zones` makes every `dns_zone_serial` and
  `dns_zone_last_refresh_timestamp_seconds` series vanish at once — the
  `absent()` condition §14 built the omit-don't-zero rule around, arriving for
  the wrong reason. The sibling `set_zone_serial` states its decision properly.

~~A `fn counter(out, name, help, v)` collapses the 250 lines to ~30 call lines
and makes the rest visible;~~ **that estimate was wrong by an order of
magnitude, and the reason is `cargo fmt`.** Both shapes were built (§19): the
helper-call shape came out at **278** lines and the table shape at **276**,
against **337**. Stock rustfmt breaks *every* element of an array or argument
list when any one of them exceeds 100 columns, and these names and help texts
do, so a four-argument call is five lines whatever it is spelled as. §12 forbids
a `rustfmt.toml`, so the length is not available to be fixed and was never the
finding worth acting on.

**What landed is the table shape, chosen on what it makes unrepresentable
rather than on the two lines between them.** A series' name, its help text and
the field it reads are one row, so the disagreement
`every_encrypted_transport_counter_reaches_the_scrape` exists to catch — a
counter declared in `Counters`, incremented, and rendered nowhere — is a missing
*row* rather than a missing block among thirty identical ones. `declare`,
`counter` and `labelled` are the three helpers; 102 `push_str` and every
`format!` are gone.

**The measurement the row asked for, taken.** Captured before and after and
diffed: **byte-identical except the `dns_catalog_members` HELP line**, exactly
as predicted, so the thirty blocks really were uniform. The three blocks using
an embedded newline instead of `\n` produced the same bytes and are gone with
the rest.

**And one it did not ask for.** A scrape was **65 allocations** and is **16**,
for the same 4 775 bytes — most of the 65 were a `format!` building a `String`
to copy out of and drop. Pinned in `rdns/tests/allocations.rs` beside the
registry counts, stable across `--test-threads` 1, 2 and 4 and on both
platforms.

**Both sub-findings fixed.** The 22 stray spaces are gone, and
`the_scrape_is_well_formed` is why they will not come back: it asserts the shape
Prometheus requires — one `# HELP` and one `# TYPE` per family in that order, a
kind from the three that exist, no sample whose family was never declared, no
padded help text — and it fails against the padded line when it is put back. The
two `if let Ok(...)` lock guards now read **through** a poisoned lock rather than
past it, with the decision written down: every writer in the file had already
chosen "a poisoned lock costs a stale gauge and the server keeps answering", and
dropping the series instead made every zone look withdrawn at once, which is the
condition the staleness alert exists to catch. A `BTreeMap` of `Copy` values is
valid after a writer panics, so there is nothing half-written to read.

**Not taken**: the macro that would declare field, series name and help together
and make the two lists one. It is what §17 would ask for, and it is a change to
`Counters` rather than to its renderer, so it wants a number of its own if
anybody wants it — the tripwire test is what stands in for it today, and it has
caught this once already.

---

### 85. `rdns::logging::init` puts a subscriber in the library — **filed and closed 2026-09-20**

`logging::init` installs the process-global `tracing-subscriber`. Both binaries
call it (`rdnsd/src/main.rs:1982`, `rdnsr/src/main.rs:497`) and nothing else
does, and it is the only use of `tracing_subscriber` in `rdns`
(`logging.rs:87`, `:94`).

Two files state the rule it breaks. The workspace manifest, on the `tracing`
entry: "The library only emits; the binaries choose where it goes."
`rdns-transport/src/lib.rs`'s header, explaining why it is not part of `rdns`:
"everything here reports to a human reading a log line … which the library may
not depend on".

**Measured on Windows.** Seven packages reach the graph only through this
dependency — `tracing-subscriber`, `matchers`, `regex-automata`, `regex-syntax`,
`sharded-slab`, `thread_local`, `lazy_static` — each confirmed with
`cargo tree -i`, every path running through `rdns`. `rdns`'s normal dependency
closure is 55 packages and would be 48. The seven units cost 7.98 s of compile.

**The refuting measurement, taken.** They are **off the critical path**: all
seven finish by 7.87 s of a 21.08 s fresh `--timings` build whose path is `rdns`
(8.67→13.66) then `rdnsd` (13.66→21.08). And `Cargo.lock` does not shrink
wherever `init` lands, because both daemons need it. So this buys nothing for a
workspace build. It buys `cargo build -p rdns` seven fewer crates, and a library
that does not make a process-global decision on its caller's behalf.

`LogLevel` moves with `init` — both binaries hold one as a clap-parsed field.
`rdns-transport` is the home its own header argues for.

#30n recorded the fact in passing — "`Cargo.lock` loses one edge and no package,
because `rdns::logging` still installs the subscriber" — and moved on. §18: that
sentence is this number.

**Done**, `LogLevel` and `init` moved verbatim into `rdns_transport::logging`.
Both predictions held exactly: `cargo tree -p rdns -e normal` is **48 packages**
where it was 55, and `Cargo.lock` moves one edge from `rdns` to `rdns-transport`
and loses no package — the whole diff is two lines. **1 248 tests on Windows
and 1 269 on Linux**, none failing, clippy clean on both sides and `cargo doc`
clean. `rdnsd` keeps its own `tracing-subscriber` **dev**-dependency for
the two tests that build a subscriber to assert what a level emits, which is
what #30n put it there for.

---

### 86. Two error enums are in the crate that cannot reach them — **filed and closed 2026-09-20**

`DnssecError` (`rdns-core/src/error.rs:141`, 57 lines with its impl) and
`BrokenCatalog` (`:198`, 43 lines) are defined in `rdns-core` and **named by no
module in `rdns-core`** — `grep` over `rdns-core/src` returns `error.rs` and
nothing else. Their only consumer is `rdns`, which already holds `TransferError`
for a reason written at the top of `rdns/src/error.rs`. Together they are 100 of
that file's 265 lines.

`rdns-core` is the crate a client links alone, which is the whole of #31:
`rdnsctl` takes it and nothing else, and its header calls it "the DNS wire
format".

**The refuting measurement, taken, and it removes a third of the finding.**
`ZoneError` looked identical and **must stay**: `rdns-present` uses it
(`record_text.rs:21`, `svcb.rs:16`) and does not depend on `rdns`, so moving it
would require `rdns-present` → `rdns`, which is a cycle. Presentation-format
parsing failing as a `ZoneError` is the reason `ZoneError` is core's, and it is
written down nowhere — put it on the enum when the other two move, or the next
sweep re-derives this.

Nothing blocks the other two: their only dependency is `WireError`, which stays,
and `rdns::error`'s `pub use rdns_core::error::*` keeps every downstream path
spelled as it is today.

**Done**, both enums and `DnssecResult` moved verbatim into `rdns::error`; no
call site changed, because the glob re-export already spelled them
`rdns::error::*`. `rdns-core/src/error.rs` is **174 lines where it was 264** —
95 moved out, five added for the note on `ZoneError`. The finding above says
265 lines and 100; `wc -l` says 264 and the cut was 95, neither counted when it
was written. The refutation is on `ZoneError` now, where the next sweep will
read it before re-deriving it. **1 248 tests on Windows and 1 269 on Linux**,
none failing, clippy clean on both sides, `cargo doc --workspace --no-deps`
clean.

---

### 87. `rdnsd`'s UDP path reads the wall clock, not `ServeContext`'s — **filed and closed 2026-09-20**

#52 made `Clock` the seam so a rate-limit test is not decided by whether two
connects straddled a second boundary, and recorded its sweep as "the four accept
loops read `ctx.clock.now()`". Two request-path sites are neither an accept loop
nor `rdnsr`'s UDP loop, so the criterion did not reach them:

- `rdnsd/src/main.rs:1310` — `udp_loop`'s `let now = tsig::now()`, which is an
  alias for `current_unix_timestamp`. That instant is threaded into the limiter,
  the admission check, the TSIG check and the response budget, so a
  `Clock::fixed` reaches none of `rdnsd`'s UDP path. `rdnsr/src/serve.rs:65` is
  the same line of the same loop, written `ctx.clock.now()`.
- `rdnsd/src/dispatch.rs:841` — `signed_error` signs with a second wall-clock
  read, where `finish` 464 lines up signs with the `now` that verified the
  request. `answer_transfer` takes `now`; `answer_update`, which reaches 11 of
  `signed_error`'s 12 call sites, does not.

**The refuting measurement, taken: it is latent.** `Clock::System` *is*
`current_unix_timestamp`, so nothing differs in production, and the TSIG fudge is
300 s. No `rdnsd` test asks for a fixed clock today —
`a_worker_answers_a_datagram_it_received` (`main.rs:3288`) drives the real loop
over a real socket and asserts nothing time-dependent. So this is §17's shape
rather than a defect: the invariant is a seam, so it is re-asserted per site, and
one site sat outside the sweep's criterion.

**Done**, and "latent" turned out to be *observable from outside the process*,
which is what made a test possible after all. TSIG is the one thing on the
request path that compares the server's instant against a number the client
chose, with a 300-second fudge (RFC 8945 §5.2.3). Sign at an instant outside
that window and the two clocks give different answers on the wire:

- `the_udp_loop_signs_and_checks_against_the_context_clock` drives the real
  `udp_loop` over a real socket with `Clock::fixed(1_700_000_000)` and a TSIG
  signed at that instant. **Reverting the one line gives NOTAUTH**; restored, it
  answers the question. Checked both ways rather than read (§1).
- `a_refused_update_is_signed_at_the_instant_that_verified_it` takes the second
  site: a valid key scoped to another zone, so the TSIG verifies and §3.3
  refuses, and the client verifies the *refusal* at the same instant.
  **Reverting `signed_error`'s clock read gives `BadTime`.**

**The fix is a type, not two careful call sites** (§17). Threading `now` into
`signed_error` put it at eight arguments, which clippy refuses at seven and
§14 says to answer with a struct. `Refused { msg, ip, now, max_len }` is the
four values every one of the twenty call sites was already passing together —
`answer_update` builds one for its eleven, `answer_transfer` one for its nine —
so the instant is carried rather than re-fetched, and a twenty-first site cannot
quietly read the clock again. 1 250 tests on Windows and 1 271 on Linux, clippy
clean on both sides.

**Counted before fixing one** (§18), and the count is what #92 is: `rdnsd` has
**twelve** production reads of `current_unix_timestamp`/`tsig::now` left, none
of them on a request path — `main.rs` 4 (two reload `signed_at`, two in the
NOTIFY *client*), `replication.rs` 4 (REFRESH/RETRY/EXPIRE timers),
`zones.rs` 3 (the re-signing policy), `control.rs` 1 (`status`'s ages).
`response_size.rs`'s read is `#[cfg(test)]` and does not count.

---

### 88. Nothing measures `rdnsr`'s answer path — **filed and closed 2026-09-20**

Every benchmark (`rdns/benches/answer_path.rs`) and every allocation assertion
(`rdns/tests/allocations.rs`) lives in `rdns` and measures the authoritative
path. `rdnsr` has neither. #45a's row already says it in prose —
"No benchmark covers `rdnsr::answer::handle_query`, so that number is a probe
rather than a bench" — which §18 says is this number.

Two things it leaves *unknown*, rather than wrong:

- **The two daemons build a reply two ways.** `ResponseWriter` — streaming, zero
  allocations per record, which is what #27b bought — is named by
  `rdnsd/src/answer.rs` and `rdns::dnssec_answer` and nowhere else. `rdnsr`
  builds a `DnsMessage`, fills `answers`, and serializes in `finish`. Whether
  that costs anything is unmeasured, and it is not obviously the same question:
  a resolver serving from cache re-serializes records it has already parsed,
  where an authoritative answer is written once from the zone.
- **`handle_query` is 432 lines** (`rdnsr/src/answer.rs:189-620`) with 15
  `return`s over ~15 documented stages, against `write_response`'s 112 lines
  over a four-case `Outcome`. §7's epilogue-skipping hazard is **answered** —
  `finish_dns64`'s header says which paths end where and why — so this is shape,
  not a defect. It is filed here because the measurement is what would decide
  whether to touch it.

The measurement: an allocation count for one cached `rdnsr` answer, beside
`rdnsd`'s. It needs a home first — `rdns/tests/allocations.rs` cannot reach
`rdnsr`, and a `#[global_allocator]` belongs in its own `tests/` file (§10).

**Taken, and it decides both halves — against touching anything.** One cache
hit, datagram in and reply bytes out, is **13 allocations**, the same on Windows
and Linux and the same across `--test-threads` 1, 2 and 3. Attributed rather
than merely recorded (§10): **2** are the parse and **3** the serialization,
which are `rdns`'s own two numbers for the authoritative path measured again
here rather than quoted, so **8** are what the resolver does in between — the
cache lookup, the records copied out of it, and the message they go into.

- **On "the two daemons build a reply two ways":** they differ by the copy out
  of the cache, not by the writing. `ResponseWriter` costs **0** with a held
  buffer and **3** without, which is what `rdnsd` pays per message on TCP;
  `rdnsr`'s `DnsMessage` serialization costs **3**. There is no per-record
  difference to unify away.
- **On `handle_query`'s 432 lines:** the cost is a constant. A second test asks
  the ratio question §10 asks for rather than a floor — the 201st cache hit
  costs exactly what the first did, 13 against 13 — so nothing here is
  quadratic in how often it is asked, which is the shape that made `log_query`
  worth rewriting. The row said the measurement would decide; it decided no.

**Where it lives, and why not where §10 says.** `rdnsr` is a binary, so a
`tests/` file cannot reach `handle_query` without a `lib.rs` and a handful of
`pub`s — and #82b measured `pub` in `rdns/src` going 517 → 651 across 77
commits with no ratchet behind it. §10 wants a separate file because a
`#[global_allocator]` applies to the whole binary; that reason is **answered**
rather than ignored, because the count is a *per-thread* tally, which is what
`rdns/tests/allocations.rs` had to invent when its own separate file turned out
to be neither necessary nor sufficient (a CI run there read 10 for a parse that
reads 6). So `rdnsr/src/allocations.rs` is a `#[cfg(test)]` module wrapping
`System`, with no dhat: the profiler is the global part, and nothing here reads
peak bytes.

That tally moved to `rdns_core::testutil::Counting<A>` rather than being written
twice (§7) — `rdns/tests/allocations.rs` now wraps `dhat::Alloc` with it and
**all 22 of its counts are byte-identical** before and after the move, checked
by running both sides.

---

### 89. A moved module left its doc comment on the next one — **filed and closed 2026-09-20**

`rdns/src/lib.rs:62` reads `/// Scratch directories, for tests only.` above
`pub mod tls_identity;`. `e26a479` (#66c) moved `rdns/src/testutil.rs` into
`rdns-core` and left the comment behind. `cargo doc` cannot catch it — a wrong
doc comment is a valid one — so it renders on the crate index today.

#20's closing note named this hazard exactly, having hit it twice in one sitting:
"deleting a function or a module leaves its doc comment behind, silently attached
to whatever follows … After any move, grep the seam for an orphaned `///`." It
was advice in prose, so nobody ran it.

**Counted before fixing one** (§18): comparing every `mod X;` that carries a
`///` against that module's own `//!` first line finds **8 in the tree and
exactly one mismatch** — this one. The other seven agree. That comparison is the
check, and it is worth having as one rather than as the same sentence a third
time.

**Filed twice.** This is **#79c** a day later, by a review that did not read
the page it was adding to. Both are closed by `73d34c9` and 79c carries the
pointer.

**Closed.** The comment is deleted rather than rewritten: `tls_identity` has a
`//!` of its own and needs no second sentence on the crate index. The
comparison is `rdns/tests/module_doc_comments.rs`, which flags a `///` on a
`mod X;` that shares no content word with either the module's name or the
first paragraph of that module's `//!`.

**Why the check is that weak.** The two comments are written to say different
things, so overlap is thin by design: the seven that agree measure 4, 1, 4, 5,
2, 1 and 4 shared words, and the orphan measures 0. The two at 1 are
`mod eviction`, which agrees only through its own name ("Shared eviction"
against "Halving a bounded cache, in one place"), and `mod dispatch`, on
"request" — so a threshold of two flags two correct comments. The margin is one
word, and that is what the tree has.

Proven by reverting (§1): with the comment back, the test names
`rdns/src/lib.rs:63`, the `///` and the header it disagrees with. Seven
declarations carry a `///` after the fix, which is the 8 above less this one.

**The walk is shared, not copied** (§7). `rdns/tests/flattened_messages.rs`
(#60) already read the workspace's source as data and owned the only recursive
`.rs` walk; a second scan would have been a second copy, so `rust_sources`
moved to `rdns_core::testutil` — the module that exists to have stopped exactly
that (#76) — and both scans call it. Both assert on the count they get back,
because a walk that returns nothing makes either test pass by reading no input.

One property worth naming: this reads source as *data*, so it checks
`rdnsd/src/control.rs`'s `mod control;` on Windows, where that file is never
compiled. §1's platform gap does not apply to it.

Verified: 1 253 tests on Windows (1 252 before) and 1 274 on Linux, clippy
clean on both sides, `cargo doc --workspace --no-deps` clean.

---

### 90. No test spawns either binary — **filed and closed 2026-09-20**

`grep -rn 'CARGO_BIN_EXE\|Command::new'` over all nine crates: zero hits outside
`rdns-core/build.rs`. Every `rdnsd` and `rdnsr` test calls into the process it is
already running in — over real sockets, which is why this is a gap in the middle
and not a hole.

What has no test in consequence: `main()`'s startup ordering, where every comment
is an argument about why a step is where it is; `--check-config`, whose whole job
is to be believed before a restart; the flag-conflict refusals §15 requires.

The only process-level coverage is CI's `image` job — serve, `/healthz`,
`/readyz`, a `dns_zone_serial` scrape, one query through `rdnsc`, and a
`docker stop` drain asserting exit 0. It covers `rdnsd` only, needs a container
runtime, and lives in YAML rather than beside the code. It is also the job that
was red for four pushes under a green tree (see the CI note above).

#74 already wrote the sentence: "`--check-config`'s output has **no test at
all** … That is not fixed here." §4's rule is the argument — "when a change is
about what happens to a *process*, the test has to involve a process" — and
`CARGO_BIN_EXE_rdnsd` needs no container and works on both platforms.

~~**The refuting check, not taken**~~ **Taken first, and it came back the other
way.** Lifting the startup sequence out of `main` is *possible* — nothing in it
needs a process — and it is not cheaper. `main` holds **28 top-level bindings
before the dry-run exit** and about twenty are still live after it, so the
lifted function hands back a struct built in one place and destructured in
another. That is #83's reload cluster exactly, measured there at 18 items and
fields and declined on it a day earlier. `CARGO_BIN_EXE_rdnsd` needs no
container, runs on both platforms, and tests the artefact an operator runs.

**One of the three items was already covered and the row did not check.**
#63i's `a_setting_the_file_can_write_is_refused_beside_config` asks clap for the
*set* of flags that conflict with `--config` and serde for the keys the file
holds, so "the flag-conflict refusals §15 requires" have had a test since
2026-09-15. What was missing there is narrower and is now covered: whether the
refusal reaches the operator as a non-zero exit and a message naming both flags,
which is a property of the process rather than of the parser.

**What landed**: `rdnsd/tests/startup.rs` (10) and `rdnsr/tests/startup.rs` (5).
`+15` tests, 1 273 → 1 288 on Windows and 1 294 → 1 309 on Linux.

**Two defects, both found by the tests rather than by reading:**

- **A `--zone-file` that will not parse reported `line 2: SOA record needs 7
  fields, got 3` and no file name.** Its two siblings in `load_zones` both name
  theirs — the directory path lists `path: error` per file, the config-`[zones]`
  path lists `origin from path: error` — and the single-file path propagated
  bare. §7's second copy, and the one an operator hits first because
  `--zone-file` is the smallest deployment. One `map_err`. Reverted against the
  fix, `check_config_refuses_a_zone_that_does_not_parse` fails.
- **`rdnsd --check-config` demanded a config file it does not need.**
  `#[arg(long, requires = "config")]` made a bare dry run answer "the following
  required arguments were not provided: --config", while `--check-config
  --zone-file x` ran happily — because `--zone-file` conflicts with `--config`,
  so clap never enforced the requirement where it would have bitten. Inert where
  it mattered, misleading where it fired, and it pointed an operator running a
  flags-only server at a TOML file.

  **That one stopped being a judgement call when `rdnsr` was read.** Its own
  `check_config` carries the argument against the attribute *in a comment* —
  "Not `requires = \"config\"`, which is where this differs from `rdnsd`'s:
  everything it checks here is flag-settable too, and a dry run that refuses the
  flag form checks the deployments that need it least" — and has never had it.
  Two binaries, one with the reasoning and one with the attribute, and the
  reasoning applies verbatim to the other (§7). Removed; a bare dry run now
  fails the way a bare start does, naming `--zone-file` and `--zone-dir`.

**What this does not cover, named rather than implied** (§18): binding sockets,
the drain, and signals. CI's `image` job covers those for `rdnsd` and remains
the one job no local `cargo` invocation stands in for — which is also why #91
matters. A process test that binds a port would be #68's shape, and #68 is open
for exactly that reason.

---

### 91. Both CI jobs no local `cargo` invocation covers were red — **filed and closed 2026-09-20**

Found while checking the README's own claims, not by a review. `gh run view
35463448583` (2026-09-19, the first push since the TLS work landed): five green,
**two red**, and they are the two this repo has already written a paragraph
about.

- **`container image`**, with `failed to read /src/rdns-present/Cargo.toml`.
  Character for character the failure #31 caused — the Dockerfile's `COPY` list
  was never told about the crate split — with `rdns-present` and `rdns-tsig`
  (#66c, #67) in place of `rdns-core` and `rdns-transport`. The CI note above
  this file's queue tells that story as a closed one. `.dockerignore` carries
  the **same list a second time**, said "all seven workspace members", and was
  stale the same way; both are fixed and both now say why the list keeps going
  stale. Verified by building the image and running it: `rdnsd 0.1.0
  (7eeb9ab-dirty)`, so the `RDNS_GIT_DESCRIBE` arg still works.

- **`licences and advisories`**, failing all three of advisories, bans and
  licences. None had ever failed before because none of it was in the graph
  before `rustls` was:
  - **RUSTSEC-2026-0285**, rustls 0.23.44 accepting TLS 1.3 handshake messages
    at the wrong encryption level (RFC 8446 §5.1). Fixed by `cargo update -p
    rustls` to 0.23.45, which is the advisory's own remedy. The transcript stays
    authenticated, so it is not a handshake forgery.
  - **`subtle` is BSD-3-Clause**, which `deny.toml`'s allow-list did not hold.
    Added, with the reason, per that file's stated policy of listing every
    licence the graph actually reaches. `BSD-2-Clause` and `Zlib` are reachable
    too and are deliberately *not* added: each is an `OR` branch MIT already
    satisfies.
  - **Four duplicate versions**, and the measurement split them in half. `rand`
    and `rand_core` were **ours**: this tree was on `rand` 0.8 and `quinn-proto`
    on 0.10. Upgrading ours is four lines — `thread_rng().gen()` became
    `rand::random()` — and it collapsed `getrandom` with them. `Cargo.lock` 218
    packages → **214**. The two that remain are named exceptions with the
    condition that clears each one written beside them, which is what `deny.toml`
    asks for rather than relaxing the check.

**The remainder, with a number rather than a sentence** (§18): `cpufeatures` is
duplicated because our `sha1` and `sha2` are RustCrypto 0.10 (on `cpufeatures`
0.2) while `chacha20`, under `rand` 0.10, is on 0.3. `sha1` 0.11.0 and `sha2`
0.11.0 are released; the migration is `digest` 0.10 → 0.11, which is not four
lines, so it was not taken here. `getrandom`'s duplicate is not ours at all:
`ring` 0.17 pins 0.2.

**What this is really a finding about.** Both jobs are the two `CLAUDE.md` §1's
rule points at and the recipe cannot reach — `image` needs a container runtime,
`deny` needs a network and an advisory database that changes under a tree that
did not. Every other job is `cargo` something a developer already runs. The
first was red for four pushes in September and nobody opened it; this time it
was red for one push and was found by checking a *README sentence* about
dependency counts. Verified: `cargo deny check` reports **advisories ok, bans
ok, licenses ok, sources ok**; 1 248 tests on Windows and 1 269 on Linux after
the `rand` upgrade, unchanged from before it.

---

### 92. Twelve wall-clock reads outside any request path — **filed 2026-09-20**

#87's count, kept because §18 says a sentence naming remaining work is a row or
it is deleted. None of the twelve is a defect and none is on a path a stranger
can reach:

| where | how many | what reads it |
|---|---|---|
| `rdnsd/src/main.rs` | 4 | two reload `signed_at`, two in the NOTIFY *client* |
| `rdnsd/src/replication.rs` | 4 | the REFRESH/RETRY/EXPIRE timers |
| `rdnsd/src/zones.rs` | 3 | the re-signing policy |
| `rdnsd/src/control.rs` | 1 | `status`'s "last heard from" ages |

**No remedy is named on purpose** (§18: a row naming a wrong remedy costs more
than one naming none). "Give them a `Clock` too" is the obvious answer and it is
not obviously right: `ServeContext` exists because four accept loops shared one,
and none of these four callers holds one — `Reloading`, the NOTIFY task, the
replication timer and `Control` would each need the seam threaded through a
constructor, which is four new parameters for a seam nothing is currently asking
for.

**The measurement that would decide it**, and it is the one #52 and #87 both
turned on: *is any of the twelve deciding a test's outcome today?* #52's row
existed because a rate-limit assertion was a coin toss, and #87's because a TSIG
fudge made a wrong clock visible on the wire. Neither is true here on the face of
it — the re-signing tests pass an explicit instant (`resign_interval_at`,
`policy_for`), and the replication timers are tested through `has_expired`, which
takes both numbers. So the row to write next is "which of these twelve has a test
that would be simpler, or an assertion that would stop being timing-dependent",
and if the answer is none, the finding is that the seam should stop at the
request path and say so in `Clock`'s own doc comment.

---

### 93. An answer's owner names carry this resolver's 0x20 scramble — **filed and closed 2026-09-20**

Found while closing #78b and deliberately not folded into it: that was the
header this resolver writes, and this is data it copies.

**Measured**, with a fake upstream that copies the QNAME into the answer's
owner name — which is what an authoritative server does, and the reason 0x20
works at all: a client asking `example.com.` gets `EXaMPLe.cOm. A 10.0.0.5`.
Both modes reach it, `forward` with one scrambled name and `recurse` with one
per hop, and `rdnsr` caches `upstream.answers` verbatim, so one resolution's
scramble is what every later client is served for the life of the entry.

**Why it is not obviously a defect.** Case is insignificant (RFC 4343) and
every name comparison in this tree folds ASCII — `Name`'s `PartialEq`, its
`Hash`, `cname_chain_shape`, the caches' keys — so nothing here reads it.
#78b's case-sensitive compare is on the *question*, which is now the client's.

**No remedy named** (§18). Rewriting an owner name is an allocation per record
on the answer path, and only a name we asked for may be rewritten: a CNAME
target's case belongs to the zone that published it, not to us.

~~**The measurements that would decide it**, neither taken.~~ **Both taken
2026-09-20, and the first one refutes the row.** The scramble does not reach the
client, and the reason is name compression rather than anything the resolver
does.

**Measured on the wire**, which is where the row's own measurement was not
taken — it read `upstream.answers`, the parsed structure, and the sentence "a
client asking `example.com.` gets `EXaMPLe.cOm. A 10.0.0.5`" describes the cache
rather than the datagram. The question section is written first, in the client's
case, and `NameCompressor::lookup` folds ASCII (RFC 4343), so an owner name
equal to the QNAME is emitted as **`c0 0c`** — two bytes of pointer at the
question — and the client parses back exactly what it asked. A name the client
did not send, `WwW.eXaMpLe.CoM.`, costs **four bytes** of upstream case
(`03 W w W`) and then points at the question for the tail. So the only case that
survives is the labels the row itself said must not be rewritten. Pinned in
`rdns/tests/case_on_the_wire.rs`, which asserts the pointer rather than the
rendered name, because the property rests on two things that can move
independently: the question being written before the answers, and the compressor
folding.

**The second measurement is therefore moot and is recorded as such**: a
per-record rewrite would cost an allocation each to change nothing for the names
that compress and to overwrite the ones that must not be touched.

**What the field does** (§4). The row assumed BIND ships 0x20 and it does not —
there is no such option and no implementation in `lib/dns/resolver.c`; ISC's
answer to RFC 5452 §9.1 is source-port randomization and cookies. **Unbound**
ships it as `use-caps-for-id` and does *not* normalize owner names either; it
arrives at the same place by the same route, because `dname_lab_cmp`
(`util/data/dname.c`) compares with `tolower` and `reply_info_encode` stores the
question's qname in the compression tree first. The one implementation that
would relay is BIND *as an authoritative server*: `named` sets
`DNS_COMPRESS_CASE` — case-**sensitive** compression — for every client not
matched by `no-case-compress` (`lib/ns/client.c`), which is why that knob exists
at all.

---

### 94. Nothing enforces a DNSKEY's protocol field — **filed and closed 2026-09-20**

RFC 4034 §2.1.2: "The Protocol Field MUST have value 3, and the DNSKEY RR MUST
be treated as invalid during signature verification if it is found to be some
value other than 3."

`Dnskey::from_record` (`rdns/src/dnssec.rs:88`) copies `protocol` into the
struct and nothing reads it afterwards except `key_tag`, which has to include
it because the tag is over the published RDATA. `grep protocol rdns/src/dnssec.rs`
is seven lines and none of them is a comparison.

Found while writing #80's tests: a DNSKEY with protocol 4 was built to make
`ZoneKeys` produce a signed-but-unusable zone, and it did not — the key parsed
and was used.

**Which direction matters.** As a signer it is nothing: we publish 3. As a
*validator* it is an interop split — `rdnsr` would call Secure what a
conforming validator calls Bogus, on a zone publishing a protocol≠​3 key. That
is the same asymmetry §8 draws for AA and NXDOMAIN: being more permissive than
the specification is a defect even when nothing breaks here.

~~**No remedy taken, because the check has a choice in it** (§18): dropping the
key in `from_record` removes it from DS matching and from the signer's own
view as well as from verification, and "treated as invalid during signature
verification" is narrower than that. The two shapes are one line each and
§19 says build both.~~ **Both built. Shape A — reject in `from_record` — is
declined, and the measurement is what declined it**: it does not fix the
defect. `verify_rrset` takes `&[Dnskey]` and `Dnskey`'s fields are all `pub`,
so a key that never went through the constructor reaches the crypto with no
check on it; shape A passed every existing test *and* left the new one failing.
That is §17's "a `pub` field beside a checking constructor", found by building
the shape rather than by arguing about it.

**What landed is shape B**, the predicate at the point of use:
`Dnskey::is_zone_key` now wants the zone flag *and* protocol 3, so all three
callers — the candidate-key filter in `verify_rrset`, `validate_dnskeys`'s DS
matching, and RFC 5011's `is_candidate_anchor` — inherit it, and a fourth
cannot forget it. One predicate, three sites, no new call-site check (§17).

**The measurement that decided it**, and it is §4's: all three implementations
reject, and two of the three fold the test in beside the zone flag exactly as
this now does.

- **BIND**, `lib/dns/dnssec.c`, `dns_dnssec_iszonekey()`:
  `(key->flags & DNS_KEYOWNER_ZONE) != 0 && (key->protocol == DNS_KEYPROTO_DNSSEC || key->protocol == DNS_KEYPROTO_ANY)`,
  reached from `validator.c`'s `select_signing_key()`, which `continue`s past
  a key that fails it. The `KEYPROTO_ANY` arm is RFC 2535's 255 and is **not**
  copied here: RFC 4034 §2.1.2 states the MUST with no exception, and neither
  of the other two allows it.
- **Unbound**, `validator/val_sigcrypt.c`, `dnskey_verify_rrset_sig()`:
  `if(dnskey_get_protocol(dnskey, dnskey_idx) != LDNS_DNSSEC_KEYPROTO) {` under
  the comment `/* RFC 4034 says DNSKEY PROTOCOL MUST be 3 */`, returning
  `sec_status_bogus`.
- **Knot**, `src/libknot/dnssec/key/dnskey.c`, `dnskey_rdata_to_crypto_key()`:
  `if (!(flags_hi & 0x1) || protocol != 0x3) return KNOT_INVALID_PUBLIC_KEY;` —
  the same two tests in one condition, at the point where RDATA becomes a
  usable verifier.

**The other measurement the row named — does any live zone publish one — was
not taken**, and it would not have changed the answer: a protocol≠3 key is
already unusable at BIND, Unbound and Knot, so refusing it here joins the field
rather than leaving it. Port 53 is intercepted on the development machine
anyway, so the probe would have measured a middlebox.

**The test, and the way it first passed for the wrong reason** (§1). The
obvious shape is the one beside it — `test_non_zone_key_cannot_sign` builds a
signature, edits the key, then repoints `rrsig.key_tag` at the edited key. That
works for the flag because clearing the flag only changes the tag. It does
*not* work for the protocol, because the key tag sits inside the RRSIG RDATA
that `signed_data` hashes: repointing the tag after signing breaks the
signature, and the test went green against the unfixed tree on a crypto failure
that had nothing to do with §2.1.2. `test_key_with_wrong_protocol_cannot_sign`
signs *after* the tag is set, so the signature is genuine and the only thing
that can reject it is the protocol field. Reverted against the fix it reports
`Verified { wildcard: None, expires: … }`.

Verified: 1 264 tests on Windows (1 262 before) and 1 285 on Linux, clippy
clean on both sides, `cargo doc` clean.

---

### 95. Nothing branches on a `TransferError` variant — **filed 2026-09-20, measured 2026-09-20**

Found closing #79a, which deleted `TransferError::Refused` because nothing
constructed it. The question that decided that — would a caller branch on it
(§3)? — has the same answer for every other variant in the enum.

**Measured**: 38 mentions of `TransferError::` outside the enum's own file,
every one of them a construction — 29 `malformed`, 3 `tsig`, 3 `timeout`, 2
`Io`, 1 `Malformed` — and **not one a match**. Every transfer failure arrives
at one place, `replication.rs:431`: a `warn!` with the error's `Display`,
`expire_if_out_of_contact`, and `timers.after_failure()`. The rcode, the
malformed stream and the timeout are one behaviour.

**This is a claim in `CLAUDE.md` §3, not only in the code**: `TransferError::Timeout`
"exists because a secondary retries a timeout and gives up on a malformed
transfer". The tree does not give up on a malformed transfer — it
retries on RETRY and expires on EXPIRE, which is RFC 1034 §4.3.5's own answer
and is probably right. So the *variant* may be justified and the *reason
written down for it* is not the one the code implements.

~~**No remedy named** (§18), because the choice is a policy question and not a
refactor~~ — **measured 2026-09-20, and neither of the two answers the row
offered is the one the field gives.**

| | REFUSED | a malformed stream |
|---|---|---|
| **BIND** (`dns__zone_xfrdone`, `lib/dns/zone.c`) | `default:` → `next_primary`, advance to the next master and retry now | `default:` → **the same arm**. What BIND separates out is different: `DNS_R_BADIXFR` retries the *same* primary with `NOIXFR` set, and `DNS_R_TOOMANYRECORDS`/`DNS_R_VERIFYFAILURE` stay on this primary and wait for the ordinary REFRESH |
| **Knot** (`event_refresh`, `refresh.c`) | `KNOT_EDENIED` | `KNOT_EMALF` — and `event_refresh` has **one** `if (ret != KNOT_EOK)` branch for every failure: RETRY, `knot_strerror(ret)` into a log line, replan. The code reaches nothing but the message |
| **NSD** (`xfrd.c`) | `xfrd_packet_drop` → next master, no state kept | `xfrd_packet_bad` → **`zone->master->bad_xfr_count++`, and at 3 `xfrd_disable_ixfr(zone)`** for that master |

**So §3's sentence is wrong and is the thing to fix.** "A secondary retries a
timeout and gives up on a malformed transfer" — *nobody* gives up. All three
retry, and this tree's retry-then-EXPIRE is RFC 1034 §4.3.5's own answer, as the
row guessed.

**But "they all just wait out RETRY" is wrong too**, which is the half the row's
dichotomy could not express. Two of the three *do* branch, and both branches are
the same shape and it is not "give up": **remember something about this master
and try a different way with it.** BIND sets `NOIXFR` and retries the same
primary; NSD counts bad transfers per master and disables IXFR after three.
Neither distinction is between REFUSED and malformed — both are about whether
*IXFR* works with this peer.

**And the measurement found a live defect on the way**, filed as **#96** rather
than folded in here. BIND's SOA-probe path branches on REFUSED specifically:

> ```c
> /*
>  * Perhaps AXFR/IXFR is allowed even if SOA queries aren't.
>  */
> if (msg->rcode == dns_rcode_refused &&
>     (zone->type == dns_zone_secondary || ...))
> {
>         goto tcp_transfer;
> }
> goto next_primary;
> ```

`fetch_soa` (`rdns/src/xfr.rs:605`) turns *any* non-NOERROR rcode into
`TransferError::malformed` and `refresh_zone` propagates it with `?`, so a
master that refuses the SOA probe and would have allowed the transfer takes this
tree out of contact until EXPIRE. `rdnsd` cannot produce that configuration
itself — it has `--allow-transfer` and no query ACL — but BIND, Knot and NSD all
have separate query and transfer ACLs, and a master that answers queries only to
its own clients while allowing transfers to its secondaries is ordinary
hardening. #57 opened the window: before it the refresh went straight to the
transfer.

**It also finds the constructor #79a could not.** `TransferError::Refused` was
deleted because nothing built it, and the site that should is this one — it
builds `Malformed` for a rcode, which is a category error as well as a missing
branch.

---

### 96. A master that refuses the SOA probe is treated as unreachable — **filed and closed 2026-09-20**

Out of #95's survey, and the one thing in it that is a defect rather than a
difference of taste.

`fetch_soa` (`rdns/src/xfr.rs:605`) maps every non-NOERROR rcode to
`TransferError::malformed`, and `refresh_zone` propagates it with `?` before it
ever attempts the transfer. So a master that answers REFUSED to a SOA query but
would have served the AXFR is, to this secondary, a master that is not there:
RETRY, RETRY, EXPIRE, and the zone goes off the air with a log line naming a
"malformed" response that was nothing of the kind.

**BIND handles exactly this**, with the reason in a comment (`lib/dns/zone.c`,
`refresh_callback`): "Perhaps AXFR/IXFR is allowed even if SOA queries aren't" —
a REFUSED to the probe goes to `tcp_transfer` rather than to `next_primary`, for
a secondary, mirror or redirect zone.

**Why the configuration is ordinary rather than exotic.** BIND, Knot and NSD all
have separate query and transfer ACLs, so "answer queries to my own clients,
allow transfers to my secondaries" is a hardening posture somebody writes on
purpose. `rdnsd` cannot produce it — it has `--allow-transfer` and no query ACL —
so this is an interop defect against the masters this tree is most likely to be
a secondary for, and it is the half of #43 the harness does not cover.

**#57 opened the window.** The refresh had no SOA probe at all before it, so it
went straight to the transfer and this could not arise. The row that added the
probe was measured on the bandwidth it saves and not on what it makes newly
fatal.

**The remedy was one match arm**, and the shape is #95's other half — with one
correction to the row's own guess. It is **not** `TransferError::Refused`
reinstated. The variant that was missing is `Rcode(ResponseCode)`, carrying the
value it caught (§2): the caller branches on *which* code, and a variant named
after one of them cannot say what the others were. `is_refusal()` is the
predicate, so the branch is a method rather than a `matches!` copied to each
site.

Both rcode sites now build it — `check_envelope` for the transfer and
`fetch_soa` for the probe, which were two spellings of one thing (§7) — and
neither says "malformed" any more. A well-formed refusal is not a malformed
message, and calling it one is what sends an operator after a parser bug that
does not exist.

`refresh_zone` takes the refusal and goes on to the transfer, skipping the
serial comparison it can no longer make; `fetch_changes` still answers
`UpToDate` for a zone that has not moved, so the no-op case is not lost, only
paid for with an IXFR instead of a query. **Only a refusal.** A timeout or a
malformed reply is a master that is not answering, and opening a second
connection to ask it something larger is the wrong move — which is also exactly
what BIND does and does not do.

One function, so both consumers get it: `rdnsd`'s replication loop and
`rdnsr`'s RPZ feed transfer both call `refresh_zone`.

**The two decisions the row left open, both settled by the survey rather than by
taste:**

- **A REFUSED to the transfer means what it meant.** It is a failure, it
  retries, it expires — and it now reports as `master answered Refused` instead
  of as a malformed transfer, which is the only thing that changed.
- **The refusal is not remembered per master, because BIND does not remember
  it.** `DNS_ZONEFLG_SOABEFOREAXFR` is cleared in `dns__zone_xfrdone` every
  time, and it is about doing an SOA *before* an AXFR rather than about skipping
  a probe; nothing in `zone.c` carries "this primary refuses the probe" across a
  refresh. NSD's per-master memory is for a bad *IXFR*, not for this. Copying
  half of BIND's behaviour and inventing the other half is how the copies in §7
  start, and the cost of not remembering is one query per REFRESH interval,
  which is hours.

~~**The measurement that would decide the shape**, not taken: whether a REFUSED
probe followed by a refused transfer costs more than the probe saves on a feed
that does answer it.~~ **Not needed, and saying why is the point** (§19): the
measurement would have priced the *remembering*, and remembering was declined on
what the field does before any number was worth taking. What the fix costs a
master that answers the probe is nothing — `an_answered_probe_still_skips_the_transfer`
pins that the probe still short-circuits a zone whose serial has not moved.

**The regression test is the §1 one.** `a_refused_soa_probe_still_transfers_the_zone`
drives the same mock master every other transfer test uses — parameterized with
a `Refuses { soa_probe, transfer }` rather than written a second time (§7), and
the two fields are separate because separate ACLs are the whole finding. Revert
the match arm and it fails. `a_master_that_refuses_both_says_so` asserts on the
variant, not the message (§3), and so does the pre-existing
`test_an_error_rcode_is_not_a_transfer`, which was one of §3's own dozen
`.to_string().contains(...)` and is fixed here because the enum moved under it.

Verified: 1 273 tests on Windows (1 270 before) and 1 294 on Linux, clippy clean
on both, `cargo doc` clean.

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
| ~~DoT / DoH / DoQ (7858 / 8484 / 9250)~~ | ~~each is a transport, and each drags in a TLS stack — the dependency argument §14 makes about the OTLP exporter applies with more force here~~ **Taken 2026-09-11 as #42**, and the reasoning is left standing because the *measurement* is what moved it rather than a change of mind: the TLS stack costs 7 packages, not a tree, because `rustls` can be told to use the `ring` this repo already links. "Applies with more force here" was a guess where §14's own argument was a count |
| SIG(0) (RFC 2931) | TSIG covers the transaction-authentication case this server actually has. SIG(0) matters for a client that cannot share a secret in advance, which is not a deployment this serves |
| DNS Cookies (RFC 7873) | round-trips as an opaque EDNS option. Implementing it properly is a second anti-spoofing mechanism beside the response budget, and the budget is the one that is there |
| `$GENERATE` | a BIND zone-file extension, not an RFC. Absent because nothing here needed it |
| white lies / minimally-covering NSEC (RFC 4470) | the denial chain is precomputed at signing time, so a lie would have to be signed online. That is a different signing model, not a feature |
| ~~key-rollover *automation* (RFC 6781)~~ | ~~rollover is manual and the signer will not delete a published DNSKEY, which is the half that matters: a key published without its private half is how every rollover starts, and deleting it would undo the operator's preparation~~ **Taken 2026-09-11 as #44f**, and the reasoning is left standing because it is still why the item is not urgent: the dangerous half is already safe. What moved it is scale, not risk |

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
and done — #35.** ~~Twice now this list has been read by a session with no queue
and used to pick the work, which is what it is for; nothing on it is marked any
more.~~ **Three times, as of 2026-09-11**: the transports went as #42, and key-rollover
automation went the same day as #44f, which makes it four. That one
went differently from the first two, and the difference is the lesson — DNAME and
SVCB were picked because the list already carried the argument, and the
transports were picked because the argument the list carried turned out to be
untested. A line that says a thing is expensive is a claim to measure
(`CLAUDE.md` §4), and this one had sat since 2026-08-03 costing nothing to check.

---

## Closed work

One line each. The reasoning, the RFC citations and the verification are in the
commit that closed it and in `docs/CLOSED_WORK.md`, which holds every section
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
| **65** | every load re-signed every zone from scratch | **filed and closed 2026-09-14**, out of 64e. `ZoneSigning::apply` signed unconditionally, so a SIGHUP, an `rdnsctl reload` or a catalog change cost a full sign of every signed zone — 27.6 s at a million records — and moved the RDATA of every RRSIG, which is the whole zone in the next IXFR delta. **The four shapes were built and the recommended one was declined** (§19, #40a's precedent again). What landed is A, keyed on the trigger: the re-signing timer reloads *in order to* refresh, so it is the one reload that may carry nothing forward, and the other two carry everything whose RRset did not move — 9.7 s against 27.6, still 53.6% saved when a tenth of the zone changes (65b). **B is declined on a measurement**: the expiry spread is a fifth of the validity and the re-signing interval a third, so every signature crosses any refresh threshold in the same tick — 0 or all 126 of a fixture's RRSIGs, never between — and the only threshold that saves work hands the refreshing run a signature with four tenths of an interval left, against the 1.4 §8 asks for. The patch was reverted and the finding kept as a tripwire on the two constants. C moved to **#64b** and then, when 64b closed without reaching the reload path, to **#64f**. The prerequisite the row called plumbing was one four-line method: `Zones::snapshot_all` |
| **63** | `rdnsr` had 39 flags and no config file | **filed 2026-09-14, closed 2026-09-15**, ten rows, filed out of 57d because a prerequisite named in prose is one nobody schedules (§18). 63a answered the split question with the compiler rather than a line count — 18 escaping items of 84 `pub`s, and 63g then measured that `rdnsr` would name **0** of them — so the module stayed in `rdnsd` and what is shared is one macro. 63h built all three shapes and kept the two declined ones as branches: the shared struct is out because `#[serde(flatten)]` makes serde buffer the table, costing every `[server]` typo its line number and its expected-key list in `rdnsd`'s existing file too. On the way, 63e found 16 defaults written twice with nothing comparing them, 63f the same bare-`pub` sweep for the `cfg(unix)` file Windows cannot compile, and 63i the one flag of 35 not refused beside `--config`. **63j is what the file existed for**: `[[rpz.feeds]]`, a policy per feed, which costs the match path nothing because `PolicyZone` has carried one since 45a. `rdnsr --check-config` closed with it |
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
| **90** | no test spawned either binary | **filed and closed 2026-09-20**. **The refuting check the row asked for went first and came back the other way**: lifting the startup sequence out of `main` is possible and is not cheaper — `main` holds **28** top-level bindings before the dry-run exit and about twenty are live after it, so the lifted function hands back a struct built in one place and destructured in another, which is #83's reload cluster measured and declined a day earlier. One of the row's three items was **already covered** and the row had not checked: #63i's clap-introspection test has held the flag-conflict set since 2026-09-15. 15 tests landed, and they found **two defects on their first run**. A `--zone-file` that will not parse reported `line 2: ...` and **no file name**, where both sibling branches of `load_zones` name theirs — §7's second copy, and the one the smallest deployment hits. And `rdnsd --check-config` demanded a config file it does not need: `requires = "config"` was inert where it mattered (`--zone-file` conflicts with `--config`, so clap never enforced it) and misleading where it fired. That stopped being a judgement call when `rdnsr` was read — its `check_config` carries the argument against the attribute in a comment and has never had it, so one binary held the reasoning and the other held the attribute |
| **83** | `rdnsd/src/main.rs` had grown two seams | **filed 2026-09-19, closed 2026-09-20**, one taken and one declined. The method was #38d's and **the criterion had to be read first**: it counts `pub(crate)` annotations, and `main.rs` is the crate root, where §17 already records that private is not private. The NOTIFY cluster is 3 annotations against 2 sealed — a revert on the letter — while what changed is **2 items unreachable from the rest of the crate and 0 newly reachable**. Taken on the second reading. `main.rs`'s code half **1597 → 1434**, 8 imports off its non-test surface, 4 of 5 tests moved with the code. The row's "one reach-back, and it is removable" was right about the one and wrong that removing it leaves none: `&Cli` went and `absolute_name` appeared, net zero. The fifth test could not move — it needs seven `main.rs` fixtures, because it is a replication test wearing a NOTIFY test's name. **The reload cluster is declined 18 against 1**: 5 items plus 13 struct fields, since `serve` builds `Reloading` and `ReloadContext` as literals — `Cli`'s shape at a third of the size, which the row had ruled out for `Cli` without noticing the two structs beside it |
| **96** | a master that refuses the SOA probe was treated as unreachable | **filed and closed 2026-09-20**, out of #95's survey. `fetch_soa` mapped every non-NOERROR rcode to `TransferError::malformed` and `refresh_zone` propagated it with `?` before ever asking for the transfer, so a master that refuses queries and allows transfers — separate ACLs in BIND, Knot and NSD, and an ordinary hardening posture — took the zone to EXPIRE. BIND branches on exactly this rcode, with the reason in a comment: "Perhaps AXFR/IXFR is allowed even if SOA queries aren't". **#57 opened the window** by adding the probe. The variant is `Rcode(ResponseCode)` and not the `Refused` #79a deleted: the caller branches on *which* code, so it has to carry the value it caught (§2). Both rcode sites build it, and neither says "malformed" about a well-formed refusal. Two decisions settled by the survey rather than by taste: a refusal to the *transfer* still fails, and the refusal is **not** remembered per master, because BIND does not remember it either — `SOABEFOREAXFR` is cleared every `xfrdone` and NSD's per-master memory is for a bad IXFR. The measurement the row named was not needed and the row says why: it would have priced the remembering, which the field declined first |
| **95** | nothing branched on a `TransferError` variant | **filed and closed 2026-09-20**, and what it was really about was a sentence in `CLAUDE.md` §3. Measured: 38 constructions of `TransferError::` outside the enum, **not one match**. The survey then said neither of the two answers the row offered was the field's. Nobody gives up on a malformed transfer — BIND, Knot and NSD all retry, and Knot's `event_refresh` has a single `ret != KNOT_EOK` arm where the code reaches nothing but `knot_strerror` — so §3's example was invented and is struck in place. But "they all just wait out RETRY" was wrong too: BIND sets NOIXFR and retries the *same* primary on BADIXFR, NSD counts bad transfers per master and disables IXFR at three. Both branches are "remember something about this master", never "give up", and neither is between REFUSED and malformed. The branch that *is* missing is **#96** |
| **93** | an answer's owner names carried this resolver's 0x20 scramble | **filed and closed 2026-09-20**, and the measurement refuted the row. The scramble does not reach the client: the question is serialized first in the client's own case and `NameCompressor::lookup` folds ASCII, so an owner name equal to the QNAME goes out as `c0 0c`, two bytes of pointer at the question. A name the client did not send costs **four** bytes of upstream case and then points at the question for its tail — and those labels belong to the zone that published them, which is what the row itself said must not be rewritten. The row's own measurement had read `upstream.answers`, the cache, not the datagram. §4's survey agrees and corrects the row twice: **BIND ships no 0x20 at all**, and **Unbound**, which does, also does not normalize — `dname_lab_cmp` folds with `tolower` and the qname is first into its compression tree. The one implementation that would relay is BIND *authoritative*, which sets `DNS_COMPRESS_CASE` for every client outside `no-case-compress`. Pinned in `rdns/tests/case_on_the_wire.rs`, asserting the pointer rather than the rendered name |
| **94** | nothing enforced a DNSKEY's protocol field | **filed and closed 2026-09-20**, out of #80's tests. RFC 4034 §2.1.2 makes a DNSKEY with protocol ≠ 3 "invalid during signature verification"; `Dnskey::from_record` copied the octet and only `key_tag` read it afterwards, so `rdnsr` called Secure what a conforming validator calls Bogus. Both shapes built (§19) and **the measurement declined the one the row leaned towards**: rejecting in `from_record` fixes nothing, because `verify_rrset` takes `&[Dnskey]` and every field of `Dnskey` is `pub` — shape A passed the whole suite and left the new test failing, which is §17's "a `pub` field beside a checking constructor" arriving as a measurement. What landed is the predicate: `is_zone_key` wants the flag **and** protocol 3, so its three callers — the candidate-key filter, DS matching, RFC 5011 anchor candidacy — inherit it. §4's survey agrees and settled the one open choice: BIND's `dns_dnssec_iszonekey()` folds the two tests the same way, Unbound checks it in `dnskey_verify_rrset_sig` and Knot in `dnskey_rdata_to_crypto_key`; BIND alone also accepts RFC 2535's protocol 255, which is not copied. The test passed against the unfixed tree on its first draft, for a reason §1 predicts — the key tag is inside the RRSIG RDATA `signed_data` hashes, so repointing the tag after signing breaks the crypto instead of testing the field |
| **81** | what #63h's macro did not reach, and one more copy | **filed 2026-09-19, closed 2026-09-20**, two rows. **81a** measured and mostly declined: of the 27 commits touching `rdnsd/src/config.rs`, 8 touch its TSIG lines and 1 of those also touches `rdnsr`'s — and that one *created* the copy — so the two tables do not co-move and the shared struct is declined; three fields of five are shared, not five, because a resolver authorizes nothing. What was taken is the list and the default under it: `TsigAlgorithm::ALL`, `::ACCEPTED_NAMES`, `::DEFAULT`, with `TsigKey::parse` coming out better than it went in. **81b** merged the two FNV-1a loops into `rdns_core::folded_hash`, and the check was the row's own instruction taken through the observable rather than by comparing the copies: six `expiry_for` offsets measured before the merge, unchanged after it, so no signature's expiry moved |
| **82** | two modules in the wrong place, and a `pub` with no ratchet | **filed 2026-09-19, closed 2026-09-20**, two rows. **82b** took the ratchet: 43 sites, 38 of them `#[cfg(test)]` fixtures that always meant `pub(crate)`, and `#![warn(unreachable_pub)]` is in all nine crate roots with what it does *not* answer written on the lint. **82a** moved `readiness` to `rdns-transport`, whose metrics server serves `/readyz`; the estimate held except that a move is two `mod` lines, not one. Both halves of the *larger* version stay declined on measurements taken in place: an `rdns-ops` crate takes no package off any binary (`cargo tree -p rdnsd` is 150 either way) and the transport link is ~450 ms of a ~3.3 s rebuild, which is a ceiling and not a saving |
| **84** | `to_prometheus_format` was 337 lines of one idiom | **filed 2026-09-19, closed 2026-09-20**, and the row's own remedy was wrong by an order of magnitude. Both shapes built (§19): helper calls 278 lines, a table 276, against 337 — because stock rustfmt breaks *every* element of an argument list when one exceeds 100 columns, and §12 forbids a `rustfmt.toml`, so the length was never available to be fixed. The table shipped on what it makes unrepresentable instead: name, help and field on one row, so a counter rendered nowhere is a missing row rather than a missing block among thirty. The `diff` the row asked for came back **byte-identical except the `dns_catalog_members` HELP line**, its 22 stray spaces, exactly as predicted. One it did not ask for: a scrape was **65 allocations and is 16** for the same 4 775 bytes, pinned. Both sub-findings fixed — `the_scrape_is_well_formed` asserts one HELP and one TYPE per family, no undeclared sample and no padded help text, and fails against the padded line put back; the two lock guards read *through* a poisoned lock now, matching the decision every writer in the file had already made, because dropping the series made every zone look withdrawn at once |
| **78** | `rdnsr`'s query path lost work at three of its exits | **filed 2026-09-19, closed 2026-09-20**, three rows, and the first was verified here while b and c were the review's reading — both held. **78a**: an `rpz-ip` rule over a cache hit dropped the prefetch the answer cache had just asked for, because `impl From<Option<Vec<u8>>> for Answered` fills `refresh: None`. Three shapes built (§19) and the one that shipped is in neither the row nor the review: delete the early `return`, since the hazard is §7's jump over a shared epilogue. **78b**: `Resolver::forward` returned the upstream's AA bit and echoed question verbatim where `recurse` normalized both, so an `rdnsr` in front of an `rdnsr` running 0x20 would have rejected its own answer (RFC 5452 §9.1) — left **#93**. **78c**: QDCOUNT = 0 was dropped by `rdnsr` and answered NOERROR *with AA set* by `rdnsd`. RFC 9619 §4 settles only QDCOUNT > 1; its QDCOUNT = 0 sentence binds firewalls, not responders. RFC 7873 §5.4 says what the query is for and that a server without cookies "will normally send FORMERR", and the peers agree: BIND 9.20.27, Knot 3.6.0, NSD 4.12.0 and Unbound 1.23.1 all answer it, all FORMERR with no OPT, and none drops it — which is the measurement that could have refuted the finding |

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
(~~RFC 6891 §6.2.2~~ **RFC 1035 §4.2.2, corrected 2026-09-11** — §6.2.2 is
EDNS *fallback* and says nothing about TCP; the citation was written from memory
and copied into four more places by #41 before anyone opened the RFC,
`CLAUDE.md` §1), and truncating would strand a client that came to TCP
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
