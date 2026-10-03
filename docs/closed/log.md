**Split into one file per number on 2026-10-03.** This page was 19,845
lines and 1.28 MB — more than an agent can read whole, so every lookup was a
grep and a partial read — and its heading "The numbered sections, in order"
was true of the first 42 of 161: the rest had been appended after the appendix
below in the order they closed. Each section is now `docs/closed/NNN.md`,
verbatim but for the `---` that separated it from the next; this file keeps
what is not a section — the preamble below, "Done so far", and the stale-queue
appendix — also verbatim. "This page" and "this file" below mean the page as
it was. Open items are `docs/issues/NNN.md` from the same day.

# rdns — closed work

Every numbered section that is finished, withdrawn or answered, and the log of
what landed. Moved out of `TODO.md` on 2026-09-05, when that file had grown to
7,989 lines of which about six thousand described work that was already done:
the queue was three screens and the archive was seventy, so the queue was the
part nobody could find.

**The prose is verbatim**, including the claims that turned out to be wrong and
the strike-throughs that correct them, because `CLAUDE.md` §11 keeps the
reasoning that produced a mistake rather than the tidy version. Two things
changed on the way across, and nothing else did. The order is numeric here,
where `TODO.md` had them in filing order; nothing was renumbered, because the
numbers are referenced from the code.

**#38, #39 and #40 came across on 2026-09-11**, having closed on 2026-09-10 and
2026-09-11 and then sat under "Open work" for a day or two — the same drift the
next paragraph records, caught this time by their rows in `TODO.md`'s table,
which said where the section still was until it was here. #38's heading was one
more instance of the fourteen: it said `filed` for work that had closed.

**And fourteen headings were corrected**, in §11's form — the original struck
through, the outcome after it. Eleven still said `filed` for work that had
closed (#7, #22, #24-#32) and three carried no status at all (#2, #14, #16). A
heading is the first thing read and was the last thing updated: #30's said
`filed 2026-09-04` while the section's own closing paragraph said every
remaining item landed on 2026-09-05, and its row in `TODO.md`'s table said
`open` on the same day. Three places, one status, two of them wrong.

**This is the page a code comment means.** 88 doc comments in the workspace
cite a section by number — `TODO.md` #30h, #27a, #25g, #26b, #28a and the rest.
They still say `TODO.md`, and they are still right to: that file carries one
line per closed item pointing here, so a reader following one of them lands on
the queue first and the reasoning one hop later. They were left alone on
purpose rather than rewritten to name this file, because an 88-comment
mechanical diff through the whole tree does not belong in an editorial change
(§12's rule about not mixing a reformat into a behaviour change, applied to
prose).

**What is *not* here:** open work, how to run any of it, the environment traps,
the architecture notes and the quick references. Those are `TODO.md`, which is
now about a fifth of what it was and is the file to read first. `docs/spec/`
says what the code does; this says what it took and why the shape is what it
is.

**Three sections have no prose of their own** and never did — #5, #8 and #9
were tracked as rows in `TODO.md`'s table. #9's 2,435 lines of finding text were
deleted on 2026-08-02 and are in `git log -p TODO.md`; what they became is
`CLAUDE.md`, which is the useful artefact. Their rows are in `TODO.md`'s closed
index with the rest.

---

## The numbered sections, in order

## Done so far

Newest first. The reasoning, RFC citations and verification for each are in the
commit message.

- **The last three of #26** (26f, 26h, 26i) — the resolver's four *lookup*
  sites take `absolute_lowered`'s `Cow` instead of an owned copy, one of them
  per record of every response; `record_type_name` returns `Cow<'static, str>`,
  so writing a zone stops building thirteen names that are in the binary
  already; and the type-bitmap walk takes set bits with `leading_zeros` rather
  than testing all eight. The filed note said `trailing_zeros`, which is the
  other bit order and would have reversed the output.
- **Hex and base64, written once** (#26a, #26c, #26d) — `utils::hex_encode`,
  `hex_decode` and `base64_encode` replace eight copies across five modules. The
  survey counted six: a third hex decoder was inline in `dnssec_chain::parse_ds`
  and a third base64 wrapper in `dnssec_key`, neither findable by the names the
  other copies used. The encoder was a heap allocation per output byte.
- **The wire encodings left the crypto module** (#26b, and #31's one
  prerequisite) — canonical name order, type bitmaps and base32hex are
  `rdns::denial_wire`, and `zone`/`zone_writer` no longer reach into
  `dnssec_denial` for them, which were the two edges blocking #31's cut. The
  second base32hex decoder went with the move; it folded case with
  `str::to_uppercase`, so it read U+017F as `S`.
- **The anomaly warnings have a caller, and their thresholds have flags**
  (#30m) — `QueryLogger::check_anomalies` had been write-only since the day it
  was written: no binary ever called it, in any commit. `logging::watch_anomalies`
  runs it every `--anomaly-interval` (default 60s, 0 off) on both daemons, and
  the four numbers that were hardcoded are `--anomaly-query-rate`,
  `--anomaly-error-percent`, `--anomaly-source-queries` and
  `--anomaly-source-refusals`, each with 0 as its own off switch, on the flags
  and in `rdnsd`'s config file. `take_stats` makes the counts per interval,
  which is what a threshold can be stated against; `rdnsr` now fills the
  counters it had been holding empty. What this keeps that `DnsMetrics` cannot
  is the source address — unbounded label cardinality is a metric's problem and
  a log line's whole point.
- **One answer-matching predicate, and the library had the weaker copy**
  (#30o, #30p) — `validation::answers_query` checks what RFC 5452 §9.1 makes a
  MUST and the socket does not: the id, the name, and the class and type. The
  resolver compared the id and the name only, and did not check QR, so a reply
  echoing another type was this query's answer. `utils::bind_addr_for` is the
  family-matched wildcard bind the same three call sites wrote out.
- **One EDNS decision instead of two** (#30h) — `response::client_edns` reads a
  request's OPT and returns either the RCODE that refuses it (FORMERR for an
  option list that does not parse, BADVERS past `EDNS_VERSION`) or a
  `ClientEdns` saying whether to attach an OPT and what to set DO to.
  `ClientEdns::mirror(payload_size)` is the reply half, so the size each daemon
  advertises stays its own. 30i and 30j resolved with it.
- **One reply skeleton instead of six** (#30g, #30r) — `DnsMessage::reply_to`
  copies what a reply must echo (id, opcode, RD, question, CD) and leaves AA,
  RA, AD, the RCODE and the OPT to the caller, which is where the six copies
  disagreed. Two defects fell out of writing it down: `rdnsr` cleared CD on
  every answer bar two, against RFC 4035 §3.2.2, and answered a two-question
  QUERY that RFC 9619 §4 says is malformed.
- **#30's one-line duplicates** (30f, 30g, 30l, 30n) — the response budget's
  four-seconds-of-burst and BIND slip of 2 were derived by hand in both daemons,
  around a `rate == 0` branch that was already dead, and are
  `ResponseLimiter::per_second`; `rdnsd`'s UDP TSIG rejection was `error_bytes`
  from 360 lines up the same file with a different length ceiling, which is now
  that function's argument; `restrict_to_owner` was written twice, and
  `rdns::persist`'s is the copy that carries the reason; `rdnsr` declared
  `tracing-subscriber` and never named it, and `rdnsd` names it only in tests.
- **`rdnsr`'s TCP transport had no admission check** (#30q) — `validate_packet`
  ran on the UDP loop and nowhere else, so on TCP none of `AdmissionCheck`'s
  pre-parse caps applied: the 16 KiB ceiling, the 12-byte floor, QDCOUNT ≤ 10,
  the per-section counts. Bounded rather than fatal — the peer completed a
  handshake and the connection ceilings still held — so a resource and
  conformance gap. The shape is §7's: the facility was built, tested and
  configured into `rdnsr`'s `Shell`, and applied on one of two paths.
- **A compression pointer points backwards, so a cycle cannot be built** —
  RFC 1035 §4.1.4 defines compression as replacing a name "with a pointer to a
  prior occurance of the same name" (the RFC's spelling, checked against the
  text rather than quoted from memory), so a forward pointer is not compression
  and no real sender emits one. Requiring each hop to land strictly before the
  previous one makes a cycle **unreachable rather than detected**: a strictly
  decreasing sequence of `usize` cannot repeat. That deleted
  `DNameUnpacker`'s `RefCell<HashSet<usize>>` and the insert/remove around every
  hop — the unpacker now holds no mutable state at all.

  **`MAX_DEPTH` stays, and its job changed**, which is the part worth reading:
  it is no longer what stops a cycle, it is what bounds the *work*. Strictly
  decreasing targets terminate, but an offset is 14 bits, so termination alone
  still permits ~16k recursive hops for one name — a stack depth a hostile
  sender would get to choose. Correctness and cost are two limits, and they are
  now two mechanisms.

  **The first hop is deliberately unconstrained**, and the comment says so: a
  name is parsed from a slice that does not know its own offset
  (`dname_from_bytes` is handed the remaining bytes), so there is nothing to
  compare the first target against. One forward jump is still accepted; every
  hop after it must decrease, which is what makes the chain finite. Recovering
  the absolute offset would mean pointer arithmetic against the message slice,
  correct only under an invariant no type here states.

  Verified: `a_pointer_chain_that_runs_forwards_is_refused` watched failing
  against the old code, where it unpacked happily to `"a.b."` (§1). Two existing
  tests needed the change and both are recorded in place —
  `test_depth_limit_prevents_deep_recursion` built its chain running *forwards*,
  so it would have passed under the new rule while measuring nothing, and now
  uses a strictly decreasing chain; `test_cycle_detection_works` still passes and
  its comment now says the self-pointer is caught on the second hop by
  arithmetic. A nineteenth allocation measurement was added because nothing in
  that file parsed a *compressed* name — the only path `DNameUnpacker`'s pointer
  following is on — and it is what makes the claim a number: **20 allocations
  with the visited set, 19 without**, measured by stashing the source and
  re-running the probe. Per *message* containing a pointer, not per name, since
  `HashSet` allocates on first insert and `unpack` cleared rather than dropped
  it — the smaller of the two claims and the true one. 1.5M mutated cases
  through `no_input_panics` with no panics, this being a pre-authentication path
  (#12).

- **A map key is a folded name, and now says so** — #13e, the half of it worth
  having. `NameKeyBuf` folds in its only constructor, so a map cannot be keyed on
  a name nobody normalized — the `cache` bug that `utils::ascii_lowered`'s doc
  comment describes. Two constraints shaped it and are recorded in §13e: the
  `Path`/`PathBuf`-style borrowed newtype needs the workspace's first `unsafe`
  and was refused, and a `(name, qtype)` tuple key cannot borrow, so the three
  tuple-keyed caches keep `String` rather than pay an allocation per lookup on a
  query path. The allocation gate caught a genuine regression (208 to 215 on a
  zone parse, 922 to 949 on a signing) and the cause was fixed rather than the
  number moved. Sixteen counts back at baseline.

- **A CLASS is not a QCLASS, and now not a `u16`** — #13d, third of three, and
  the last of it. `Class(u16)` on `ResourceRecord` and `ZoneRecord`, with the
  same one-way conversion into `QueryClass` that `Rtype` has into `Qtype`. It
  could not be done before OPT stopped parsing as a resource record: an OPT's
  CLASS field is the requestor's UDP payload size, the same two-meanings problem
  `Ttl` had in the field next door. RFC 2136's repurposing of a record's CLASS —
  ANY and NONE in an UPDATE's prerequisite and update sections — is what
  `From<Class> for QueryClass` and `Class::is_meta` are for. Sixteen allocation
  counts unchanged.

- **A TTL is unsigned, and clamped once where the bytes are read** — #13d,
  second of three. `Ttl(u32)` with `Ttl::from_wire` applying RFC 2181 §8 at the
  parse boundary, replacing fourteen hand-written `ttl.max(0) as …` sites and
  five conversions back. The hazard #13d predicted was real: an OPT record's TTL
  is a flags word, and it was still being parsed *as a `ResourceRecord`* even
  after OPT moved into its own field — so clamping would have erased the
  extended RCODE, the EDNS version and the DO bit. The additional section is now
  read through an `Additional::{Record, Opt}` enum and an OPT never becomes a
  record at all, which is the alternative to the conditional invariant "clamp
  unless it is rtype 41". Sixteen allocation counts unchanged.

- **OPT is not a resource record, and no longer stored as one** — #13d, first of
  three. `DnsMessage.edns: Option<Edns>` replaces an OPT record hidden in
  `additionals`, which cost eight linear scans of that `Vec` per message in
  `lib.rs` alone and made every filter over the section responsible for
  remembering to spare it. It also closes a malformed state nothing rejected:
  **two OPT records in one message**, which RFC 6891 §6.1.1 says MUST be FORMERR
  and which used to be read as one and written back as two. The option list is
  kept unparsed on purpose — if reading it were part of parsing the message, a
  bad list would fail `try_from_bytes`, and `rdnsd` answers a parse failure with
  no bytes at all, so today's diagnosable FORMERR would become a client timeout.
  Two tests changed to match the new shape and three were added. Fifteen
  allocation counts unchanged, one measurement moved with its number intact.

- **A TYPE is not a `u16` either, and `answer_signatures` proves why it matters**
  — #13c, second half. `Rtype` newtypes `RecordData.rtype`, `Rrsig.type_covered`,
  the NSEC type bitmaps and `utils::record_types`. It immediately found a fifth
  hand-written copy of the ANY rule in `dnssec_answer::answer_signatures`, which
  had survived the first half **because that function still took a `u16` and its
  callers were changed to pass `.to_u16()`** — a newtype stops paying the moment
  a signature is widened back to let it through. `Rtype::is_meta` replaces the
  three-way comparison in RFC 2136 §3.4.1's prescan, and the magic type codes in
  `ParsedRecord::decode`/`encode` and `NameCompressor::write_rdata` had to become
  named constants to compile. All fifteen allocation counts unchanged.

- **A QTYPE is not a TYPE, and now it is not a `u16` either** — #13c, first half.
  `Qtype` is a `repr(transparent)` newtype on `QuerySection.qtype`, so
  `rr.rdata.rtype == query.qtype` stops compiling. It was written twice in
  `resolver.rs` and both were wrong for QTYPE=ANY: one decided whether a CNAME
  chase was finished, the other whether an answer was *negative*, which sent the
  DNSSEC validator hunting a denial proof and turned a verifying ANY answer into
  `Bogus("... was denied without an NSEC or NSEC3 proof")` — SERVFAIL under
  `--dnssec-validate`, for a question nothing on that path rejects. Watched
  failing first. `Qtype::matches` is now the one home of what ANY means;
  `zone::of_type`, where it was got right, keeps a pointer instead of a second
  telling. All fifteen allocation counts unchanged.

- **One name fold, one containment test, one label count** — #13b.
  `utils::names_equal`, `absolute_lowered` and `label_count` replace seven
  hand-written copies of the same three rules, and `utils::normalize_domain_name`
  — a `to_lowercase` in the public API that folds U+212A KELVIN SIGN into `k`,
  which `CLAUDE.md` §8 forbids and which had no callers but the obvious name — is
  deleted. Two of the copies the plan had not found: `xfr::in_bailiwick`, whose
  removal also fixes a trailing-dot mismatch, and `ixfr::key`. Two duplicated
  tests deleted with them. Comparing two names went from 2 allocations to 0,
  measured against the old shape rather than described; the other fourteen counts
  are unchanged.

- **`OpCode` carries the value it could not name** — #13a, opens #13.
  `OpCode::Other(u8)` replaces an `Unknown = 15` sentinel that was parsed with
  `from_u8(...).unwrap_or(OpCode::Unknown)`. 15 is a real value in a four-bit
  field, so eleven of the sixteen opcodes went back onto the wire as 15 —
  including **6, which is DSO (RFC 8490) and assigned**, checked against IANA
  rather than assumed. `rdnsd` echoes this field into the NOTIMP reply RFC 1035
  §4.1.1 says must carry the client's, so a DSO client got a reply to a question
  it had not asked. The third instance of the sentinel pattern after
  `QueryClass::None` and `ResponseCode::Unknown`, and the last `num_derive` user
  in the workspace. Fourteen allocation counts unchanged.

- **Dynamic UPDATE, the half with no policy in it** — opens #10.
  `rdns/src/update.rs` reads an UPDATE message into a checked list of
  prerequisites and changes and evaluates the prerequisites against a zone:
  RFC 2136 §2.4's five prerequisite forms, §2.5's four update forms, §3.1's zone
  checks, §3.4.1's prescan and §3.2's four distinct rcodes. It stops before
  mutating anything, because the four policy items #10 lists all sit past that
  point. Two rules that pass a careless test were each watched failing against
  the careless version first: §3.2.3 compares a value-dependent prerequisite
  against the whole RRset as a *set*, and §2.4.4's "in use" is `holds_name`
  rather than `name_exists`, so a wildcard or an empty non-terminal does not make
  a name exist. Twelve tests.
- **The pre-authentication panic audit, and a fuzzer to keep it true** — closes
  #12, the last numbered item. No reachable panic: 1.4 million mutated messages
  through `validate_packet`, `try_from_bytes`, the TSIG scan, both EDNS readers,
  the zone lookups, `dnssec_answer`'s four proof builders and the writer, in a
  debug build so overflow panics rather than wrapping. What it did find was the
  amplifier: `DnsCache` used `.lock().unwrap()` on all four lock sites, two of
  them on `rdnsr`'s query path, and poisoning is permanent — one panic under that
  lock, ever, would have made every later query panic too (`CLAUDE.md` §6). All
  four degrade now with the direction commented at each, and the regression test
  *panics* rather than failing against the old code. `RateLimiter`'s two
  monitoring functions had the same shape and now fail in the same direction as
  the rest of that file. `rdns/tests/no_input_panics.rs` runs 1,506 cases in the
  suite and takes `RDNS_FUZZ_ITERATIONS`/`RDNS_FUZZ_SEED` for a soak.
- **A benchmark harness that measures optimized code, and the item it closed** —
  closes 9e's last two, and with them #9 entirely. `rdns/benches/answer_path.rs`
  under criterion: fourteen benchmarks, release profile, baseline comparison.
  One whole answer is 522 ns (parse 151, look up 60, serialize 123); a full-size
  60-record response 5.07 µs; a zone miss in 10k records 159 ns. It closed #13 on
  its first run — verifying the same RRset at 1 and 20 records costs 31.03 and
  32.78 µs, so the canonicalization the item wanted removed is 102 ns per record
  against 31 µs of ECDSA, and `verify_rrset` returns on the first signature that
  verifies so it usually happens once anyway. The header carries the number that
  keeps all of this honest: a `sendto`+`recvfrom` pair is 3.6-4.1 µs, so the
  whole suite is ~6% of a query. Seven `bench.rs` debug-build floors deleted
  (lib count 624 → 617); the two guarding a complexity class stayed. Cost: 22
  dev-only packages.
- **A request's EDNS parameters, read once and without the option list** —
  closes 9e item 12 and with it every allocation item on the list.
  `DnsMessage::edns_header` walks the OPT RDATA to check it and returns the three
  fields the answer path reads (payload size, version, DO) as a `Copy` struct;
  `edns()` still exists for a caller that wants the options. Both daemons called
  it twice per query and built the option list both times. Measured with the
  query a real resolver sends — EDNS0, DO, a DNS cookie, which is what BIND and
  Unbound send by default and what every earlier probe here lacked: 24,707 blocks
  → 20,707 over 1,000 queries, four per query. The check and the parse are one
  walk with two closures, so FORMERR means the same thing to both, with two tests
  holding them to it. `rdns/tests/allocations.rs` is one `#[test]` now, because
  the eight it had were being mis-counted by libtest's own bookkeeping on another
  thread — 15 where the answer is 7, three runs in five on Linux.
- **Four more per-query allocation sites, one of them a wrong answer** — closes
  9e item 11. `compression::write_name` 5 → 2 (the vector of label offsets is an
  iterator; a name already in the table is not copied to look it up), `dname`
  parsing 3 → 2 (a name with no compression pointer in it is already unpacked),
  and `find_zone_for_query` 3 → 0 — which also stopped folding case with Unicode
  `to_lowercase`, where U+212A KELVIN SIGN made a query select a zone it differs
  from on the wire and get that zone's NXDOMAIN with AA set (`CLAUDE.md` §8). Its
  containment test is `utils::is_at_or_under` now, shared with the zone index
  (§7). Measured over 1,000 UDP queries against a rebuilt `HEAD`: 20,712 blocks →
  13,707 — 25.7 allocations per query down to 13.7 across the two changes.
  `msg.queries.clone()` was the third item on the list and stayed, with its
  reason. Five exact assertions in `allocations.rs`, three of them moved here and
  each watched failing first.
- **A zone lookup key that borrows** — closes 9e's largest item. `absolutize`,
  `normalize_name`, `lookup_key` and `origin_key` return `Cow<str>`, and
  `HashMap<String, _>::get` takes a `&str`, so a query for a name that arrived
  absolute and lower case — every query off the wire — reaches the index without
  allocating. Two of `absolutize`'s three cases were copying a string to produce
  itself. Measured over 1,000 UDP queries against a rebuilt `HEAD` beside it:
  25,715 blocks → 20,712, five per query, both sites gone from the profile. Four
  assertions, two of them exact allocation counts (5 → 1 for the three lookups
  behind one answer), each watched failing against the reverted code and
  identical on Linux.
- **A readiness probe and a container image** — closes 9d's last operability
  item, and with it 9d. `GET /readyz` on `--metrics-listen` is 503 (naming the
  zones) until every `--secondary` zone has transferred at least once, and 200
  after; `/healthz` stays liveness-only. A primary is ready as soon as it is
  alive, because its zones are loaded, signed and verified before `serve` binds
  anything — the finding's "bound but still parsing 40 zones" state does not
  exist here, and a cold **secondary** serving REFUSED until its master answers
  is the one that does. The latch is one-way on purpose: every replica of a zone
  expires in the same second, so readiness that followed EXPIRE would empty the
  rotation rather than shrink it. Proved by running a secondary against a master
  that was down and then bringing the master up. The `Dockerfile` runs
  unprivileged on 5353 with no `HEALTHCHECK` (an orchestrator probes over the
  network; the image should not carry an HTTP client to talk to itself), and CI's
  new `image` job builds it, runs it, probes both endpoints, asks it a DNS
  question with the `rdnsc` inside it, and requires a clean SIGTERM stop. The
  same was run by hand on the Linux side: 31 MB, no `.git` anywhere in it, and a
  secondary container started before its master answered `/healthz` 200 and
  `/readyz` 503 until the master appeared.
- **`rdnsd` has a control socket, and `rdnsctl` talks to it** — closes 9d's
  control-channel item. `status`, `reload` and `dump <zone>` over a Unix socket
  at mode 0600, because the servers that put a control channel on TCP all
  authenticate it and the ones that do not use a socket. `reload` reports what
  happened — exit 1 and the parse error, with the previous zones still being
  served — where `kill -HUP` reported nothing. No per-zone reload: a reload is
  the whole set or nothing. Unix only, refused rather than ignored elsewhere.
  (`652e4d5`)
- **No task per UDP datagram on `rdnsd`, and a bound on `rdnsr`'s** — closes
  9d's admission-control item and 9e's 1,536-bytes-per-datagram one, which were
  the same call site. `rdnsd` answers inline from `--udp-workers` tasks sharing
  the socket; `rdnsr` keeps its spawn, because a recursion is seconds of waiting,
  and bounds it with `--max-inflight-udp`. Measured over 1,000 queries against a
  rebuilt `HEAD` on the same box: 7.45 MB in 34,487 blocks → 2.88 MB in 31,574,
  the task site gone and 996 responses built in 16 buffers. (`652e4d5`)
- **Both daemons have log levels** — closes 9d's log-volume half. `--log-level`
  and `--quiet` on `rdnsd` and `rdnsr` through one `rdns::logging::init`, with
  `RUST_LOG` on top. Nothing per-packet is above `debug`, so 50 malformed
  datagrams cost **0 log lines** at the default level where they used to cost 50,
  and `format!` no longer runs for a line nobody wants. No in-process rate
  limiter: journald's per-unit one is in the README's unit instead. 11 crates,
  measured. (`3777192`)
- **`rdnsd` compiles on Unix** — it had not since SIGHUP reloading was written,
  because `signals.next()` needed a `StreamExt` nothing imported and the module
  is `#[cfg(unix)]`. Found by running the suite on Linux for the first time.
  Fixed by using `tokio::signal::unix`, which `rdns::shutdown` already used, and
  deleting `signal-hook` and `signal-hook-tokio`. (`3777192`)
- **A secret file's mode is checked when it is read** — one
  `persist::ensure_private` for the TSIG and DNSSEC paths both, and
  `write_atomically_private` restricts the temporary file *before* the rename so
  a new private key is never briefly world-readable. (`3777192`)
- **The zone load and the state fsync are off the runtime** — `spawn_blocking`
  for the reload, and the state write happens after the mutex guard is dropped
  rather than across the fsync. `load_zones_from_source` is honestly sync now; it
  was an `async fn` with no await in it. (`3777192`)
- **A reload no longer blocks every query for the length of its diffs** — planned
  under the read lock and recorded under the write lock, with a generation
  counter deciding whether the plan survived the gap. 99.5% of sampled queries
  were locked out during a reload before; ~0.3% after. (`3777192`)
- **`--user`/`--group` closed as won't-fix** — privilege separation belongs to
  the service manager, and `User=` with an ambient capability is stronger than a
  setuid drop rather than equivalent to it. (`3777192`)

- **`rdnsd` signs zones, and answers a DO-bit query from one** — closes #2, the
  last feature on this list. `dnssec_key` generates and stores private keys and
  makes signatures; `zone_signer` publishes the DNSKEY RRset, signs every
  authoritative RRset, and builds an NSEC or NSEC3 chain over every name in the
  zone — delegation points and empty non-terminals included, which is what makes
  a missing DS and a NODATA at a name holding nothing provable rather than merely
  asserted. `dnssec_answer` then decides what a *reply* needs, which is more than
  the signatures: a wildcard answer goes out with a denial of the name actually
  asked for, and an NXDOMAIN with a denial of the wildcard that could have
  answered it. `--generate-keys` makes the pair and prints the DS for the parent;
  `--nsec3` and `--nsec3-opt-out` pick the other chain, with RFC 9276's empty
  salt and zero iterations. `dnssec_validation_mode` gets its first caller:
  every signature in a zone is verified against the zone's own keys before
  anything is served from it, and `--require-signed` makes an unsigned zone a
  refusal to start. Verified with **dnspython**, which validated every RRset
  served under both chains, and confirmed the delegation's NS RRset unsigned and
  its NSEC listing NS without DS. See "Architecture: signing a zone".
- **CNAME chains are validated as chains, not just as RRsets** — closes an item
  under #2. Every RRset in an answer verifying under its own zone's keys says each
  record is authentic and nothing about whether together they answer the question:
  a genuine CNAME beside a genuine A record for an unrelated name is two valid
  RRsets and no chain. `dnssec_chain::cname_chain_shape` walks from the question,
  follows each CNAME, and requires every record to be on that path — bounded,
  loop-detecting, case-insensitive (0x20 makes that not optional), and stopping
  before the first hop when the question was itself for a CNAME. A Secure verdict
  now depends on it. The resolver's `chain` filter is the first line during
  recursion; this is the one that holds for an answer arriving whole from a
  forwarder. See "Architecture: DNSSEC".
- **Wildcard synthesis: the positive half of RFC 8198** — closes an item under #1.
  A validated wildcard answer is one signature covering a whole set of names, the
  same as a validated NSEC, so it is kept under the wildcard and answers for other
  names it reaches, re-owned and with its signature attached — which verifies at
  the new name unchanged. Two rules keep it honest: the name must be proved absent
  by a cached covering NSEC, and the wildcard must be `*.` plus the name's
  *immediate parent*, derived from the queried name rather than searched for, so
  `*.example.com.` cannot answer for `a.b.example.com.`. See "Architecture:
  aggressive use".
- **NSEC3's NXDOMAIN path is resolved end to end** — closes an open item under #1.
  Every NSEC3 test here built its own records and called the proof functions
  directly, which checks the proof logic and nothing about the path to it. The
  signed test hierarchy now serves an NSEC3-proved NXDOMAIN and the resolver
  validates it Secure: collected across hops, parsed off the wire, verified as an
  RRset at owner names that are base32hex of a real hash. Plus the test that the
  test means something — with the closest-encloser record removed the verdict must
  stop being Secure, because a proof that merely *covers* the name would let an
  attacker holding one covering record deny anything in the zone (RFC 5155 §7.2.2).
- **Special-use names are answered locally, not asked about** (RFC 6761, 6762,
  6303) — closes #6. `localhost` and its subtree resolve to loopback, `.local` and
  `invalid.` are NXDOMAIN at once, and the reverse zones for address space that is
  not globally unique are answered here rather than described to a public server.
  New `special_names` table, consulted before every cache in `rdnsr` because for
  these names a cache lookup would already be one query too late. Never AD, and not
  skipped for CD clients — CD is about DNSSEC, not about wanting a stranger's
  opinion of `localhost`. Negative answers carry a synthetic SOA so downstream can
  cache them. The `example.` names are deliberately left ordinary. Verified by
  forwarding to TEST-NET-1, where anything answered was answered locally by
  definition. See "Architecture: names that never leave".
- **RFC 5011: the resolver follows a trust anchor as it rolls** — closes #2's
  rollover item. A trust anchor is believed out of band, so changing one was an
  out-of-band event; the root KSK rolls, and a validator that has not been updated
  fails closed on the whole internet. New `rfc5011` module and
  `rdnsr --auto-trust-anchor <file>`: the zone's own signed DNSKEY RRset is the
  announcement channel, a successor is adopted after 30 days of continuous
  publication, and a key that revokes itself — verified as having signed the very
  RRset that revokes it — stops being an anchor, configured DS or not. State lives
  in a writable presentation-format file, so a restart does not restart a hold-down.
  `SharedAnchors` makes the live set replaceable, since following a roll without a
  restart is the entire point.
  **Verified against the real root**, which was not expected to work here: port 53
  is intercepted and recursion generally fails, but a one-hop `./DNSKEY` query is
  answered, so the probe ran for real. Key 20326 was adopted at once as the
  built-in DS's match and 38696 — a successor KSK the root is currently
  pre-publishing — entered its hold-down; a restart left the clock where it was.
  That run also found a flaw no unit test would: the literal reading of §4 tracks
  every key in the RRset, which meant tracking the root's ZSK, a key nobody will
  ever anchor and one the root replaces quarterly *without* revoking — so the set
  of permanently trusted keys would have grown every three months. Only secure
  entry points are tracked now. See "Architecture: following a trust anchor".
- **A secondary announces what it transferred, so a tree cascades** — `announce_zones`
  ran at startup and on SIGHUP, which are the moments a *primary* learns of a
  change; a secondary learns of one by transferring it and said nothing. So the
  first level of a replication tree updated at once and every level below it waited
  out a refresh timer — which for a typical SOA is hours. RFC 1996 §3.2's "master"
  is whoever serves the zone to someone, which a secondary in the middle is, so
  `refresh_once` now announces the zone whose serial just moved, to the same
  `--also-notify` targets. Spawned rather than awaited, for the same reason the
  primary's announcements are. Found by running a three-node tree for the IXFR
  work and noticing the bottom node waiting; fixed and re-verified there, with
  REFRESH at an hour so nothing but the NOTIFY could have moved it — the change
  reached the bottom in about seven seconds, incrementally.
  `Replication` now bundles what a refresh task shares (zone map, delta log, state
  file, zone directory, notify targets) rather than passing six parameters that
  are not independently choosable.
- **IXFR-in: taking an increment rather than the zone** — step 5 of #7. A refresh
  now asks for the difference whenever it holds a version to differ from. The
  answer's shape is positional and a client may not assume it got what it asked
  for: the second record of the stream decides, and `IxfrAssembler` hands over to
  `AxfrAssembler` when it is not an SOA rather than duplicating the rules about
  what a transfer may contain. Applying is `ixfr::apply_changes` — rebuild the
  zone, never edit it, which is why `Zone` has no record-removal API. A deletion
  for a record we do not hold is counted and logged, not fatal: the record is meant
  to be gone either way, and failing would strand the secondary on a version it can
  never leave. Verified as a three-node tree, where S2 took an increment from S1
  covering the change S1 had itself received in full — 8 records on the wire against
  12 — and ended up with S1's zone exactly. See "Architecture: incremental
  transfer".
- **IXFR-out: an increment instead of the whole zone** — step 4 of #7. An AXFR
  moves everything whenever anything moves, which is what makes a short REFRESH
  expensive. New `ixfr` module: `DeltaLog` remembers the difference between the
  versions of each zone this process has held (bounded, 32 steps), computed at the
  moment a zone is replaced — BIND's `ixfr-from-differences` without the on-disk
  journal, which is a thing to build when dynamic UPDATE arrives and not before.
  The response is RFC 1995 §4's positional shape, with four logged reasons to fall
  back to a full transfer, and a chain with a gap in it is never partially applied:
  a client that took one would hold a zone that never existed, with a serial saying
  it was current. Gated by the same ACL as an AXFR, since it may answer with the
  whole zone. Over UDP the answer is §2's single-SOA "come back over TCP". The log
  is derived state, so it moves with the zone map in one call and a withdrawn zone
  takes its history with it. Verified against dnspython's own `inbound_xfr`, which
  applied our increment and landed on the right zone. See "Architecture:
  incremental transfer".
- **`rdnsd` can be a secondary** — step 3 of #7, and the one that makes the rest a
  replication story rather than a pile of parts: it could hand a zone out (AXFR)
  and announce a change (NOTIFY), but could not *be* a replica of anything.
  `--secondary zone@master[:port][#key]`, new `xfr` (the client half of a transfer)
  and `secondary` (timers, master specs, the state sidecar) modules. What arrives
  is checked before it is believed — opens and closes with the apex SOA, every
  record in bailiwick, AA set, bounded length, TSIG chained across envelopes — and
  a zone is swapped in whole under the write lock, written to disk by `zone_writer`
  and recorded in a line-based sidecar. EXPIRE is enforced, including across a
  restart, which is what the sidecar is really for. A NOTIFY from a master now
  refreshes at once; from anywhere else it is REFUSED. Verified live between two
  `rdnsd` processes with dnspython as the client. See "Architecture: the secondary
  role".
- **A request's sections were being judged by one blanket rule, and it had now
  killed three features** — `validate_header` rejected *any* request carrying an
  answer or authority section, before anything read the opcode. That is right for
  QUERY and wrong for everything else: a NOTIFY carries the zone's SOA in its
  answer section (RFC 1996 §3.7) and an IXFR request carries the client's SOA in
  its authority section (RFC 1995 §3). The symptom is always silence — the message
  is dropped and nothing says why — which is exactly how the additional-section
  version of this rule left EDNS dead on arrival. Found by watching a live NOTIFY
  fail to reach a secondary that was configured to act on it. Now: answers are
  forbidden for QUERY only, and every section is capped rather than prohibited.
- **A UDP receive error took the whole server down** — on Windows, replying to a
  client that has already closed its socket earns an ICMP port-unreachable, which
  is reported as `WSAECONNRESET` on the socket's *next* `recv_from`. Both daemons
  treated any receive error as fatal, so the loop returned and the process with it.
  A stray ICMP report says nothing about the socket's health; it is now skipped and
  receiving continues, while errors that are not that are still fatal, because a
  server that cannot receive is not serving. Unix only reports this on connected
  sockets, which is why the shape of the bug is invisible there.
- **A zone this server does not hold is REFUSED, not NXDOMAIN** — NXDOMAIN is an
  assertion about the DNS as a whole, which we have no standing to make about a
  zone we hold nothing for, and a resolver caches it (RFC 2308) so the lie
  propagates. REFUSED says the truth and sends the resolver to the rest of the
  delegation. It is what BIND, NSD and Knot answer here, and it matters more now
  that a zone can be *withdrawn*: an expired secondary answering NXDOMAIN would
  take its zone off the internet for as long as anything cached the answer.
- **A zone-file writer, and a file replaced atomically** — step 2 of #7, and what
  everything below it needs: a secondary that fetches a zone has nowhere to put it.
  New `zone_writer` (text presentation format, so the load path is the one already
  parsed and tested) and `persist` (temporary sibling → fsync → rename, which
  replaces an existing file on both Unix and Windows). The rule the writer is built
  around is byte-exactness rather than equivalence — a signature covers RDATA octet
  for octet — so a record is spelled type-specifically only when re-encoding it
  provably reproduces the stored bytes, and goes out in RFC 3597 §5's generic
  `\# <len> <hex>` form when it does not. That fallback is also what lets a type
  this library has no parser for be persisted at all. On the load path: `TYPEnnn`
  is now read and written wherever a type is named, and a type bitmap listing an
  unrecognized name is an error instead of dropping it silently. Cross-checked
  against dnspython, record by record, on the wire bytes. See "Architecture:
  writing a zone back out".
- **`rdnsd` serves both transports from one process** — it ran one per transport,
  which cannot hold writable state: two servers over the same zone file would race
  to write it, and step 1 of #7 exists for that reason. Also fixed on its own terms:
  the rate limiter, validator, logger and metrics were one set *per transport*, so a
  client had two query budgets and the metrics each saw half the traffic — now one
  shared `Server`. The `udp`/`tcp` subcommands are gone. See "Architecture: one
  process per server".
- **NOTIFY (RFC 1996), and the opcode field was being read wrong** — a secondary
  had no way to hear that a zone changed except its own refresh timer. New `notify`
  module and `--also-notify`: sent on zone load for every zone whose serial moved
  forward (RFC 1982 arithmetic, so a wrap is not read as a rollback), carrying the
  SOA, retried until acknowledged. An incoming NOTIFY is answered *as* a NOTIFY
  with NOTAUTH — this server is a primary, not a secondary — and other opcodes get
  NOTIMP rather than being treated as lookups. See "Architecture: NOTIFY".
- **The opcode decode masked instead of shifting** — `hi & 0x70` where the field
  needs `(hi >> 3) & 0x0f`. It dropped the low bit and never shifted, so IQUERY
  arrived as QUERY, and NOTIFY, UPDATE and STATUS all arrived as `Unknown`; the
  *write* side shifted correctly, so the two disagreed. Invisible because every
  test used QUERY, whose value survives any mask — the same shape as the RRSIG
  expiration/inception swap. NOTIFY could not have worked at all before it.
- **TSIG (RFC 8945)** — `--allow-transfer` authenticates by address, and an address
  is a claim the network makes on a peer's behalf. New `tsig` module: HMAC-SHA1 /
  256 / 384 / 512 over the RFC 8945 digest, `--tsig-key [alg:]name:base64` on both
  subcommands, verification before anything is answered, signed replies to signed
  queries, chained MACs across the envelopes of a zone transfer, and BADKEY /
  BADSIG / BADTIME / BADTRUNC as distinct answers. A key authorizes a transfer from
  any address; the log line says whether a key or an address allowed it.
  Cross-checked against dnspython in both directions, which is the check the DNSSEC
  work never had. See "Architecture: TSIG".
- **A response *byte* budget, not just a query count** — the rate limiter counted
  requests, which is blind to the thing an amplification attack is made of: one
  small query can pull a 2.5 KB answer, and a forged source address turns that
  into someone else's traffic. `security::ResponseLimiter` meters bytes leaving
  per client (`--response-rate`, UDP only — a TCP query has completed a handshake,
  so there is nobody to reflect at), with a four-second burst so ordinary use
  never sees it, and RRL-style *slip*: every second response over budget goes out
  truncated rather than dropped, which cannot amplify and tells a real client to
  retry over TCP. The tracking table is bounded, because a spoofed flood comes
  from every address there is. Measured: 32.7 KB/s out with the budget off,
  13.2 KB/s with it on. See "Architecture: amplification".
- **AXFR (RFC 5936), refused by default** — zone transfer, which the server had no
  handler for at all. The response is the sequence RFC 5936 §2.2 asks for: the SOA
  first, the zone, the same SOA last, split into messages that fit a TCP frame, so
  a client can tell a finished transfer from a cut one. Gated on
  `security::TransferAcl` — addresses or CIDR prefixes, **empty by default, which
  refuses everyone** — and every attempt is logged whether or not it was allowed.
  TCP only: over UDP it is FORMERR, since a zone does not fit a datagram and the
  protocol cannot say "there is more". An AXFR for a name that is not a zone apex
  we serve gets NOTAUTH, not the enclosing zone. See "Architecture: zone transfer".
- **Negative caching, the plain kind (RFC 2308)** — a "no" costs as much to obtain
  as a "yes" and was cached only when it validated, which for most deployments
  meant never: every repeat of a failing lookup was a fresh walk. New
  `NegativeCache` keyed the way each kind of "no" applies — NXDOMAIN by name (all
  types, and everything below it per RFC 8020), NODATA by (name, type) — with the
  TTL from the SOA as RFC 2308 §5 defines it, bounded at an hour, and nothing
  stored without an SOA or from a bogus answer. `rdnsd` now puts its zone's SOA in
  negative answers (RFC 2308 §2.1/§2.2), without which nothing downstream could
  cache them at all. Replaces a `DnsCache::put_negative` stub that stored an empty
  entry under type 0, recorded neither rcode nor SOA, and had no callers. See
  "Architecture: what rdnsr remembers".
- **TXT is framed as `<character-string>`s (RFC 1035 §3.3.14)** — it was stored as
  one unframed blob, so the RDATA on the wire had no length prefix and every
  correct client read the first character of the text as a length byte and lost
  it. `ParsedRecord::TXT` is a `Vec<Vec<u8>>` now: a *sequence*, because two
  strings are not one string joined; and *bytes*, because a character-string is
  arbitrary octets — as `String` a binary TXT failed to decode, and decoding
  happens while reading the message, so one such record made the whole response
  unparseable. The zone parser splits on quotes rather than whitespace (`"a b"` is
  one string, `a b` is two), and a string over 255 bytes fails the load instead of
  being silently split. This also fixes the canonical form, so a signed TXT RRset
  verifies. Confirmed against c-ares.
- **The zone parser reads the files people actually write** — parentheses group a
  record across lines (RFC 1035 §5.1), which every real SOA uses and which used to
  fail the load outright; `;` inside a quoted string is data, not a comment, which
  is what TXT records are full of; and `$INCLUDE <file> [origin]` works, resolved
  next to the including file via the new `parse_zone_file_at`. Owner names are now
  resolved against the origin in force at their line, so `$ORIGIN` applies to what
  follows it rather than retroactively. See "Architecture: zone storage".
- **Zone lookup is indexed** — one `HashMap` from owner name to record positions,
  built at load time, replacing a filter over the whole record vector that
  allocated two `String`s per record compared. 10k-record zone, one lookup:
  **4.4 ms → 0.685 µs** (`bench_zone_lookup` holds the floor). `Zone`'s `origin`
  and `records` are private now, since the index is derived from both. Fixed on
  the way past: an existing name no longer gets the wildcard's records mixed into
  its answer. See "Architecture: zone storage".
- **Wildcard NODATA is no longer refused (RFC 4035 §5.4, RFC 5155 §8.7)** —
  `proves_nodata` insisted on an NSEC whose owner *is* the queried name, so a
  zone with a wildcard got SERVFAIL for every type the wildcard does not carry:
  when a wildcard answers, nothing sits at the name to hold a type bitmap. It now
  falls back to the other shape — the name shown absent, plus the record at the
  wildcard its closest encloser publishes. The NSEC3 half is RFC 5155 §8.7's
  closest-encloser proof, now shared with the NXDOMAIN path as
  `nsec3_closest_encloser` (§8.3) rather than written twice. `proves_nodata`
  takes the zone name, as `proves_nxdomain` already did. The denial cache is
  untouched by design: it consults only the record *at* a name, so answering from
  a wildcard would be the RFC 8198 §5.3 synthesis it deliberately does not do.
- **Wildcard answers now demand their NSEC (RFC 4035 §5.3.4, RFC 5155 §8.8)** — a
  wildcard's signature verifies at every name the wildcard could expand to, so a
  verified expansion was being served as Secure on the strength of a signature
  that says nothing about the name asked for. `validate_records` now reports each
  expansion and `validate_wildcard_proofs` requires a signed denial of that name,
  including that the wildcard belongs to its closest encloser — without which a
  genuine `*.example.com.` RRset re-owned onto a name under an existing
  `b.example.com.` validates, since `b`'s own NSEC covers it. New
  `dnssec_denial::proves_wildcard_expansion`. Also fixed: the wildcard's *own*
  RRset read as an expansion of itself (the labels field never counts the `*`),
  which would have demanded a proof that the wildcard does not exist. See
  "Architecture: DNSSEC".
- **Aggressive use of validated denials (RFC 8198)** — a validated NSEC/NSEC3 is
  a signed statement about a *range* of names, so `NsecCache` stores the range
  and answers every name in it without asking again. New
  `dnssec_denial::canonical_sort_key` puts canonical name order into bytes so a
  `BTreeMap` can do the covering lookup that `DnsCache`'s `(name, type)` key
  cannot express. Guards: Secure material only, never across an opt-out NSEC3
  span, never below a delegation, wildcard denial required for NXDOMAIN, TTL
  bounded by the proof. See "Architecture: aggressive use".
- **DNSSEC validation on the resolve path** — the chain of trust is walked from
  a trust anchor down to the answer and enforced behind `rdnsr
  --dnssec-validate` (`--trust-anchor <file>` to override the built-in ICANN
  root key). New modules `dnssec_chain` (anchors, states, per-step verdicts) and
  `dnssec_denial` (NSEC/NSEC3, canonical name ordering, type bitmaps,
  base32hex); `dnssec` rewritten around RFC 4035 §5.3.2 signed-data assembly.
  See "Architecture: DNSSEC".
- **The DNSSEC primitives had never run against a real signature, and did not
  work.** Every test fed `b"test"` as the signed data, so nothing exercised the
  crypto. Once real signatures were put through it: the signed-data assembly
  did not exist (no RRSIG prefix, no canonical ordering, no original-TTL
  substitution, no wildcard reconstruction); the DS digest omitted the owner
  name, so no real DS could ever match; ECDSA keys were handed to `ring` without
  the SEC1 `0x04` prefix, so algorithm 13/14 could never verify; the algorithm
  dispatch mapped 8 to ECDSA and 5/7 to RSA/SHA-256 and SHA-512, all wrong
  against IANA; and `construct_rsa_public_key_der` emitted DER with broken
  length encoding and no sign padding (replaced by `ring`'s
  `RsaPublicKeyComponents`, which needs no DER at all).
- **RRSIG expiration and inception were swapped in the codec** — RFC 4034 §3.1
  puts expiration first. Invisible to a round-trip test because both halves
  agreed; against a genuine RRSIG it read an expired signature as current.
- **The root name decoded as `""` rather than `"."`** — every other name gets
  its trailing dot from its last label and the root has none. With 0x20 on, the
  reply check compares the echoed question byte-for-byte, so *every query for
  the root name was rejected as a mismatch*. Only surfaced when the validator
  started asking for `./DNSKEY`, which it does before anything else.
- **NSEC name ordering was string comparison**, not the RFC 4034 §6.1 ordering
  by label from the right, so a range check would accept names outside the gap
  it was given (`a.z.example.com.` vs `b.example.com.` sort opposite ways).
- **IPv6 root hints + `--root-hints` flag** — the built-in hints now ship both
  families (the 13 AAAA addresses too), interleaved v4/v6 so either stack is
  reached in the first hop or two. `query_server` binds a send socket of the
  target's family, which is what actually makes AAAA glue and the v6 hints
  reachable — a v4-wildcard socket cannot connect to a v6 address, so they were
  dead before. `parse_root_hints` reads the published `named.root` format, and
  `rdnsr --root-hints <file>` overrides the built-ins (fails loudly on a file
  with no addresses; ignored when forwarding).
- **RTT-based server selection** — `ask_any` now tries a zone's servers
  fastest-known-first, folding each round trip into a smoothed per-server RTT
  (EWMA, α=0.25) and charging a failure the full timeout, so a slow or dead
  nameserver is demoted after one try instead of being waited on every query.
  Unmeasured servers keep their input order; forwarding reuses the same path.
  `RttStore` shares the delegation cache's capacity bound (0 disables it).
- **0x20 case randomization + reply validation** — outgoing query names get
  their letter case scrambled (draft-vixie-dnsext-dns0x20) and every reply is
  now checked to actually answer the query: matching transaction id, and a
  question that echoes the name sent — case-sensitively when 0x20 is on, which is
  what makes the casing anti-spoof entropy. Neither check existed before; a reply
  from the right address was taken on faith. `zero_x20` flag, default on.
- **QNAME minimization (RFC 9156)** — the walk sends each server only the label
  it is delegating (root learns the TLD, the leaf reaches only the authoritative
  server), probing with QTYPE=NS so a zone cut shows as a referral and a plain
  in-zone name as NODATA. Empty non-terminals cost one extra probe; NXDOMAIN on
  an ancestor short-circuits (RFC 8020). `qname_minimization` config flag,
  default on.
- **Async resolver** — the whole resolve path (`resolve` → `recurse` →
  `resolve_from_root` → `walk` → `ask_any` → `query_server`/TCP fallback) is
  `tokio::net` now, so each round trip is an `await` and `rdnsr` awaits `resolve`
  directly instead of pinning a `spawn_blocking` thread for the sum of the hops.
  Glueless-delegation recursion is boxed (`Box::pin`) to keep the future finite.
- **Delegation cache** — resolution starts at the deepest known zone instead of
  the root every time; stale entries fall back to the root rather than failing.
- **Real recursion, with forwarding as a mode** — root hints, referral walking,
  both bailiwick rules, glueless delegations, CNAME chasing, query budget.
  `RecursiveResolver` (which only ever forwarded) became `Resolver`.
- **`rdnsr` logs why a resolution failed** instead of turning everything into an
  undiagnosable SERVFAIL.
- **Consolidated the wire-writing primitives into `dname`** — one bounds-checked
  write, one label encoder, one statement of the pointer constants, instead of a
  copy on each side of the dname/compression split.
- **Fixed a parser panic on truncated names** — `Label::try_from_bytes` indexed
  unchecked, so a hostile packet panicked the task rather than erroring.
- **Concurrent multi-query TCP in both daemons**, plus `rdnsr`'s TCP listener (it
  had none, so the TC=1 → TCP retry every client makes was refused) and the
  RFC 1035 §4.2.2 framing `rdnsd`'s TCP listener never implemented.
- **Name compression on output (RFC 1035 §4.1.4)** — 170-record A RRset went
  5314 → 2764 bytes (−48%). Owner names always; RDATA names only for
  NS/CNAME/PTR/SOA/MX (RFC 3597 §4 forbids it for newer types); canonical DNSSEC
  output stays uncompressed. Verified against c-ares.
- **TCP fallback on truncation** — a TC=1 UDP answer is re-issued over TCP on the
  same upstream.
- **EDNS0 / OPT (RFC 6891)** — codec, options, the 12-bit extended RCODE,
  BADVERS, payload-size negotiation. Fixed `validate_header` rejecting every
  request with an additional section, which had made `rdnsd`'s EDNS support dead
  on arrival.
- **`DnsMessage::to_bytes` serializes records at all** — responses used to claim
  N answers with an empty body.
- **`rdnsd` answered NXDOMAIN for its own zone** — three independent causes in
  zone matching and zone-file parsing.
- **The `RecordData` raw-storage refactor** — a 24-byte
  `{ rtype: u16, rdata: Box<[u8]> }` holding uncompressed wire bytes, down from a
  ~96-byte three-level enum; the typed view is a flat `ParsedRecord` produced on
  demand, as NSD/Knot/Unbound do it. An earlier plan to *split* the enum was
  abandoned: a Rust enum is sized to its largest variant, so it gave zero
  happy-path benefit.

---



---

## How the queue kept going stale, kept verbatim

`TODO.md`'s preamble and its open-work table are below as they stood on
2026-09-05, immediately before the rewrite that moved everything above into this
file. They are here rather than deleted for the reason they were written that
way in the first place: **a count in a preamble is a claim that goes stale
whenever the list below it changes**, and this is nine instances of it happening
to the same three paragraphs, each corrected in place rather than reworded
(`CLAUDE.md` §11). The strike-throughs are the record.

What the rewrite did about it is not a better paragraph. It is a shorter list:
the queue in `TODO.md` is now one open section and one inventory, and everything
finished is a row in a table beside a pointer here. A summary of two items
cannot drift from them. Whether that holds is a question for the next reader who
finds this page wrong.

### The preamble as it stood

#### `# rdns — TODO / Next Steps` — the title and preamble

Working notes for picking this up cold. **`CLAUDE.md` is the companion to this
file**: this one says where the work is and how to run it, that one says which
mistakes this codebase has already made and the rules that follow from them.
Read both before planning; the first rule in `CLAUDE.md` is why a green suite
here has twice not meant what it looked like.

**`docs/spec/` is the third of the three, added 2026-08-03**, and it answers the
question the other two do not: *what does this actually do*. Seven files derived
by reading the code, not by reading intent — the wire codec, the zone model, each
daemon, DNSSEC, operations, and an RFC conformance table that collects every
known deviation and gap in one place. Reach for it when you need the behaviour
rather than the history; reach for here when you need to know what is open.
`docs/ARCHITECTURE_REVIEW.md` is the review that produced it and #17-#19.

**Starting cold, read in this order:** "Current state" for what works today and
what is unproven, "How to run" for the commands, the four environment traps under
"Verifying" (each has cost an hour), and then "Where to pick up next".

**Nothing here describes a particular machine.** Paths, the Linux image and its
invocation, the git remote, what is installed and why port 53 misbehaves live in
`CLAUDE.local.md`, which is untracked and imported by `CLAUDE.md` — moved out on
2026-08-04, because a checked-in file describing one laptop is wrong for every
other reader and silently so. What stayed is every *measurement* and every caveat
needed to trust one; those say "the development machine" and the local file says
which. The
"Architecture" sections describe what exists and why it is shaped that way — they
are the part of this file that is not written down anywhere else. Finished work
is one line each under "Done so far", pointing at the commit that carries its
reasoning, RFC citations and verification.

**The short version, if you read nothing else:** **#12, #13, #14 and #16 are
closed and #15 is withdrawn** — this line read "every numbered item through #14
is closed" until 2026-08-03, which was never true of #7 step 6, #10 or #11, all
three of which the "Open work" table already listed as open two screens below.
Corrected in place rather than reworded (`CLAUDE.md` §11), because it is the
third time a *count* in a preamble has gone stale on this page and the shape is
the lesson: read the table, not the summary. The operational
shell is finished; #9's five-way review went in full, its last performance item
closed by measuring rather than fixing it; #12's audit found no reachable panic
and left a fuzzer behind to keep it that way; and **#13 moved five families of
invariant out of per-call-site checks and into the types, in twelve commits,
fixing seven live defects on the way** — an opcode field that rewrote eleven of
its sixteen values, a QTYPE=ANY answer that SERVFAILed a good signature, two OPT
records where RFC 6891 requires FORMERR, an escaped dot encoded as two labels,
two distinct wire names collapsing onto one string, a fifth copy of the ANY rule,
and `rdnsd` answering a response sent to its UDP port.

**What is left**: a stretch goal (#11), a feature half-built on purpose (#10),
and **three sections filed on 2026-08-03 from an architecture review** —
**#17**, the one confirmed bug in the tree (a TCP length prefix that wraps to 0
on a TSIG-signed answer near 64 KB, so the connection is dropped with no answer);
**#18**, seven operational facilities that exist in the library and are wired
into `rdnsd` only, leaving `rdnsr` with no rate limit and no metrics at all; and
**#19**, eight smaller items, five of which are stragglers of consolidations that
caught most copies and missed one. The review also left `docs/spec/` behind — a
seven-file description of what the code actually does, with the RFC deviations
and gaps collected in one table. Also still true: **CI runs now, and its first
run failed** (the test's fault, fixed locally, unpushed).

**A second review, 2026-08-04, aimed at algorithmic shape rather than
structure**, filed **#23-#26**. The one to read first is **#23**: `rdnsr
--dnssec-validate` spends up to a second of CPU on a single query — timed, not
argued — because the aggressive-denial cache re-hashes the queried name once per
cached NSEC3 record while holding one global mutex. #24 is three costs that grow
with a number the operator chose (zones served, records per message, zone size),
#25 is eight small per-answer items on paths #9e already measured, and #26 is
another crop of §7 duplicates — one of which, 26j, is a correction to this page:
the wrecked string literal #19h records as fixed had never been fixed, and now
is, with the assertion that would have caught it.

**A third pass, 2026-09-04, asked whether the three binaries reimplement each
other**, and filed **#30** and **#31**. The library answers no: everything deep
has one implementation and every binary calls it. What is written twice is the
transport layer — `rdnsd` and `rdnsr` hold a TCP accept-and-frame loop, a
shutdown epilogue and an admission pipeline that are the same code with the
comments reworded, and `rdnsc` holds a second copy of the resolver's client
exchange.
**The one thing to read is 30q**, which the duplication led to rather than being
one: `rdnsr` calls the admission check on its UDP path and not on its TCP path,
so the 16 KiB ceiling, the QDCOUNT cap and the pre-parse section caps do not
apply to a TCP peer. **#31 is the boundary question that follows**, answered with
dependency counts rather than taste — not a `platform` crate and not a `net` one;
yes to one for the transport, **`rdns-transport`**, because §3 forbids `anyhow`
in `rdns` and it needs it; and the cut that would actually pay is `rdns` itself,
which two synchronous CLIs currently compile tokio and ring through. **Both sections were
reviewed against the code the day they were filed** and four claims did not
survive it; they are struck through in place, and what the review moved is at the
end of #30.

**A fourth pass, 2026-09-05, asked #30's question of the whole tree** rather
than of the transports, and filed **#33**: is anything written twice, would a
generic or a trait collapse it, and are the modules and crates cut in the right
places. The last of those three is the one that produced almost nothing, and
**five candidates were dropped — four by rules already on this page**, which is
the half worth reading; a `dnssec/` module directory died on #31's own rule that
a split without a measurement is motion. The one defect is **33b**, and it is in
a shipped binary: `DnsMessageBuilder` resolves its question type through an
**RTYPE** table, so ANY, AXFR and IXFR find nothing there and the question is
dropped in silence — `rdnsc` cannot ask an ANY query at all, which is why
nothing here exercises the RFC 8482 path #9f fixed in `rdnsd`. **33a is the one
with teeth**: `NegativeCache` kept the per-insert `min_by_key` scan that
`DnsCache` was fixed away from, measured at 14.6 µs against 0.26 at the same
bound, on the mutex every query takes. Two of this filing's own claims died on
review — a `zone_writer` bug that is not reachable, and a trait that is the
wrong shape for what is actually duplicated — and both are struck through in
place.

Build and test with the four commands at the top of `CLAUDE.md`;
`cargo bench -p rdns` is the fifth. **Do not push** — commit locally and leave
it; the reason is in `CLAUDE.local.md` and it is about the account, not the code.
Nothing is half-applied and the tree is clean.

**This file was cut from 6,067 lines to about a third of that on 2026-08-02**,
when the last numbered item closed. What went was the full text of findings that
are now fixed — 55 "original finding follows" blocks and a 2,435-line review
section — because that reasoning is in three better places: the commit that fixed
each one, the rules distilled in `CLAUDE.md`, and `git log -p TODO.md`, which
still has every word of it. What was kept is what a cold reader cannot get
elsewhere: how to run the thing, why it is shaped as it is, and which claims on
this page turned out to be wrong.

---

### The open-work table and "where to pick up next", as they stood

#### `## Open work` — the preamble and the table

The numbers are **stable identifiers, not reading order.** They are referenced
from the code (`ixfr.rs:16` points at "#7 step 6") and from each other, so they
are never renumbered.

**#14 and #16 are closed; #15 is withdrawn; #7 and #10 closed on 2026-08-03.
~~**One thing is open** and the table is where it is: **#22**, filed 2026-08-04 as
the redirect #11 produced — the zone lookup turned out to be hash-bound rather
than cache-bound.~~ — **stale within the day, for the sixth time. #23-#26 were
filed later on 2026-08-04** from a second architecture review, this one aimed at
algorithmic shape rather than structure. ~~**#23 is the one with teeth**: a query
that costs a second of CPU on `rdnsr --dnssec-validate`, provoked and timed.~~
**#23 is fixed** (`9715c3c`, 2026-08-04) — seventh time, same day again. ~~#22 and
#24-#26 are open.~~ — **all of #24 fixed 2026-08-05**, so read the table: #22,
#25 and #26 are open. ~~#26 too~~ — **#25 and #26 both closed 2026-09-04**, in
six commits; which is the eighth time a sentence here has gone stale and is left
corrected rather than reworded, for the reason the next paragraph gives. Of the
numbered sections, **#22 is the only one of #22-#26 still open**.

~~#11, a stretch goal blocked on hardware counters the development machine cannot read~~ —
**answered no on 2026-08-04**, and the blocker did not exist: the Linux side has
a virtualized core PMU, and the question was settled with cachegrind anyway.

**#21 is not open work**, it is the inventory: the four deviations from the RFCs
this code makes on purpose, and the list of things not implemented. Neither was
recorded here before, so the only evidence they had been *decided* rather than
overlooked lived in `docs/spec/`, which is not what anyone reads before starting.

~~Four things are open ... #17, #18 and #19, filed 2026-08-03 from an
architecture review~~ — all three closed on 2026-08-03, the day they were filed.
That is the fifth correction to this paragraph, and by now the paragraph is the
exhibit rather than the record: **do not read a count here, read the table.**

~~#7 step 6 (persisted deltas, no longer blocked — see below), #10 itself (the
writing half is in too; what is left is incremental re-signing and the
journal)~~ — both of those went the same day, which is the fourth time this
paragraph has gone stale.

This line has now gone stale five times and is left corrected in place every
time rather than quietly reworded, per `CLAUDE.md` §11. It first read "everything
numbered through #13 is closed", which was already untrue of three items when it
was written; then "three things are open", which #17-#19 falsified the day they
were filed; and now the #10 parenthetical, falsified the same day by three
commits against it. **The lesson is in the shape, not the wording: a count in a
preamble is a claim that goes stale whenever the list below it changes**, which
is why the table is the thing to read and this paragraph is not. The third
instance says something the first two did not, though: the stale claim was not a
count this time but a *status*, and a status goes stale faster than a count
does. The fourth went stale within hours of the third, which is the same lesson
with the volume turned up.

What each item was, and where its reasoning now lives — the commit that closed
it, and the rule it became in `CLAUDE.md`:

| # | what it was | closed |
|---|---|---|
| **1-4, 6** | recursor, DNSSEC and NSEC3 follow-ups, zone lookup, special-use names | see "Closed work" below |
| **5** | smaller items: AXFR, TSIG, NOTIFY, IXFR, amplification, negative caching, `$INCLUDE`, TXT framing | all done; see "Done so far" |
| **7** | the secondary role, in six steps | **all six done 2026-08-03.** Step 6, persisted deltas, waited on #10 and landed with it: `rdns/src/journal.rs` |
| **8** | what signing turned up — the re-signing timer and its serial | done |
| **9** | what a five-way review found: 48 defects in six groups (9a-9f) | **all done, 2026-07-27 → 2026-08-01.** The patterns became `CLAUDE.md`, which is the useful artefact; the 2,435 lines of finding text are in `git log -p TODO.md` |
| **10** | dynamic UPDATE (RFC 2136) | **done 2026-08-03**, seven commits. Reading (`8ff74db`, `eff4fcb`), applying and the serial (`fedf8d9`), authorization (`fedf8d9`), dispatch and persistence (`fedf8d9`). Incremental re-signing (`fedf8d9`) and the journal (#7 step 6) closed it |
| **23** | `NsecCache::synthesize` hashes once per cached NSEC3 record, under one mutex | **fixed 2026-08-04** (`9715c3c`), the day after it was filed. 1 124 ms → 1.28 ms on the same probe. The fix is a type — `Nsec3Params`, the triple a hash is a function of — plus the map lookup the key was already there for, and the proof moved out from under the lock. One of the four filed boxes did not survive being checked against the code: NSEC3 hides how deep a cached name is, so the depth bound it asked for is not available to take |
| **24** | three costs that grow with something the operator chose | **all three fixed 2026-08-05.** Zone selection was O(zones per query) — 55 µs at ten thousand zones, now 32 ns and flat, keyed on `NameKeyBuf` with a walk up the QNAME, and the walk brought a second multiplier with it that the client picks. Name compression was O(n²) in the records of one message, so a 400-record transfer envelope cost 130.7 µs to serialize and now costs 42.8; the index that fixes it is built lazily, because the threshold that helps a transfer hurt a 60-name response by 26%. And an AXFR held the zone three times over before the first byte went out; the envelopes are an iterator now, at 10.5× less peak memory, which needed `Arc<Zone>` in the map because the lock cannot be held across a socket write |
| **25** | per-answer waste on paths #9e already measured | **closed 2026-09-04**, filed 2026-08-04. Eight items, each small: the zone walked three times per answer, 64 KiB zeroed per TCP reply, eight atomics per latency sample, a `String` per label per canonical comparison. Includes the negative results — LTO, and the SIMD shapes that are not worth it. **Two of the eight corrected themselves on the way**: 25a's three walks were down to two before it was started, because #28b and #27c had removed the others, and 25h was already fixed and never ticked. 25g's win is the one worth remembering — an uppercase *search* is linear in the name's length and a fold is flat, and the length is the client's |
| **28** | work the answer path does and need not | **filed 2026-09-01; 28a-28c done and 28d answered *no* the same day.** The companion to #27, and its first item is larger: six clock reads per query cost 144-155 ns on both platforms, and four of them want the same instant. Also a closest-encloser walk computed and discarded on every positive answer and run twice on every NXDOMAIN, a delegation walk that cannot find anything in a leaf zone, and four global mutexes per datagram recorded as an unmeasured ceiling rather than a cost. Two of five candidates died on inspection and are kept |
| **29** | the resolver half never got #27's pass | **filed and closed 2026-09-04**, five commits; #25b, #25e and #26e closed with it. #27 and #28 gated `rdnsd`'s answer path at three allocations a query; `rdnsr` was never in that series and `rdns/tests/allocations.rs` cannot see it. The same walks, the same hashing, the same reply buffer, with the fixed copy sitting beside them |
| **30** | the two daemons' transports are one transport written twice | **open, filed 2026-09-04 and reviewed the same day.** Seventeen items: fifteen duplicated between `rdnsd` and `rdnsr` — the TCP transport whole, the five transport constants, the shutdown epilogue, the admission pipeline, five hand-written reply skeletons, the EDNS mirroring — two between `rdnsc` and the library, and ~~**30q, the one defect: `rdnsr` never applies the admission check to TCP**, so on that transport the 16 KiB ceiling, the QDCOUNT cap and the pre-parse section caps do not run~~ — **30q fixed 2026-09-04**, the only defect in the section and the first thing done from it, followed the same day by 30f, 30l, 30n and both halves of 30g — which was not a tidy-up after all: the skeleton it removed was hiding `rdnsr` clearing the CD bit RFC 4035 §3.2.2 says to copy, and 30r beside it — then 30h, which closed 30i and 30j behind it. Then 30p and 30o, which is where the *library* turned out to hold the weaker copy of a check `rdnsc` had right, and 30m — answered by reading what the facility was *for* rather than by deleting it. What is left is 30a-30e, on #31. The library itself came out clean. Reviewing the filing against the code struck four of its claims, including two that had the direction backwards; what the review moved is recorded at the end of the section |
| **31** | where a crate boundary would pay | **done 2026-09-05**, filed 2026-09-04 and corrected the same day. `rdns-transport` holds #30's transport; `rdns-core` holds the wire format, which takes a client from 67 packages to 35 — two crates and not the three the plan drew, because splitting DNSSEC from net saves a client nothing and a split without a measurement is motion. Not `platform` and not `net`: both would move code that already has a home. Yes to a crate for #30's transport, **`rdns-transport`**, and the argument is `anyhow` rather than tidiness — §3 forbids it in `rdns` and the transport needs it; the name is checked against `domain`, hickory, Knot and BIND rather than chosen, and "shell" was already taken by #9d. The cut that pays is `rdns` itself: `rdnsc` is a synchronous CLI compiling 78 packages, tokio's 18 and ring's among them, floored at clap's 21. ~~32 of 41 modules touch neither~~ — an import count is not a partition; walking the edges found exactly two blocking ones, both `zone`/`zone_writer` reaching into `dnssec_denial` for wire helpers with no crypto in them, which is #26b from the other side |
| **32** | `Shell`, `Served` and the other unnamed bags | **closed 2026-09-05**, filed 2026-09-04: the two renames that needed no crate went that day, and the other three boxes went with `rdns-transport` the next — `ServeContext` was not a step towards 30e's shared pipeline, it *was* the pipeline's parameter list, which is why it landed in the same commit. Four field-only structs that are "what a task needs that is not the answer" and say so in no name — three renamed, `Control` kept as its module's principal type — one of them in a word #9d already spends on something else. The finding under the rename is that `rdnsr::Shell`'s five fields *are* five of `rdnsd::Server`'s twelve, so 30e's shared pipeline already has its parameter list written twice; naming it `ServeContext` in `rdns-transport` is the extraction rather than a step towards it. Carries the rule for what earns the suffix, since a policy struct and a request handler both must not |
| **33** | a fourth pass: duplication, generics, and where the modules are cut | ~~**open, filed 2026-09-05**~~ — **closed 2026-09-06**, corrected here on 2026-09-06 while adding #34's row. This table said `open` while §33 four thousand lines above said `closed`, which is the drift the paragraph above it describes, one page later and about itself. Filed 2026-09-05. #30's question asked of the whole tree rather than of the transports. Eight items, and **five candidates dropped** — four of them by rules already on this page, which is the half worth reading. The one defect is **33b**: `DnsMessageBuilder` resolves its question type through an *RTYPE* table, so ANY, AXFR and IXFR find nothing there and the question is dropped in silence with no `else`; `rdnsc` cannot ask an ANY query at all, provoked at the command line, so nothing in this tree exercises the RFC 8482 path #9f fixed in `rdnsd`. **33a is the one with teeth**: `NegativeCache` and `NsecCache` kept the per-insert `min_by_key` scan `DnsCache` was fixed away from — 14.6 µs against 0.26 at the same bound, linear in it, and on the mutex every query takes. 33c is one line of workspace manifest for five packages, verified compiling on Windows and Linux. The rest are consolidations: an `apex_soa` with one public copy in the wrong module and two private re-implementations of it, and the RFC 8945 §5.3.1 envelope chain written three times. Two of the filing's own claims died on review and are struck through in place — a `zone_writer` bug that is not reachable, and a trait that is the wrong shape for what is actually duplicated |
| **27** | what a zero-allocation answer path would take | **five of six stages done, 2026-09-01 → 2026-09-05; 27d withdrawn.** A query cost 21 allocations when it was filed and costs **2** now, both of them in the parse — the question `Vec` and the QNAME `String`, which need the message shape 27d declined. Nothing on the answering side allocates at all. Four stages, measured on `rdnsd` under dhat rather than argued: a resolver's actual query (EDNS0 + DNS-0x20) costs 21 allocations, and 13 of them come out with no new lifetime anywhere. Filed with the payoff stated first — ~1% end to end — because the reason to do it is a gate asserted at zero, not speed. Carries three traps that would each be silent: the compressor rewinding with the buffer, echoing the folded QNAME to a 0x20 resolver, and UPDATE needing the unpacker the query path does not |
| **26** | helpers written twice, and hand-rolls with a standard spelling | **closed 2026-09-04**, filed 2026-08-04; 26j done the same day. Ten items, nine of them duplicates. 26j is the correction to this page: the wrecked string literal 19h records as fixed had never been fixed, and the wrong claim reached three documents. Fixed with a test that holds the whole message rather than a substring — the old assertion was true of the broken literal. **The rest went on 2026-09-04**: 26b took the module split #31 needed and 26a/26c/26d turned out to be eight copies rather than six — two of them, an inline hex decoder and a third base64 wrapper, carried none of the names the others did, which is this section's own thesis about reading over grepping. 26i's filed fix was wrong (`trailing_zeros` for a bitmap whose bit 0 is the high bit) and is corrected in place |
| **22** | the zone lookup is hash-bound | **closed 2026-09-05**, filed 2026-08-04 from #11's measurement. The first direction is done — one map instead of two takes a miss from 1,875 to 1,402 instructions, 25%, where the estimate said 200. The second is a decision and the answer is **no**: the threat model is written down in the section, and it says the prize (~2% of a query) and the risk (a constant factor on a lookup, not a complexity class) are both small, which argues for leaving a DoS-resistant hasher where it is |
| **11** | data layout and CPU cache friendliness | **answered no 2026-08-04.** Measured with cachegrind: a miss costs 2,786 instructions and under 0.08 D1 misses, a hit 1,052 and 6.4 — all L2-resident, zero LL misses either way. There is no pointer chase to remove. The `perf` blocker it carried for months was checked and did not exist; the probe is `rdns/examples/zone_lookup_probe.rs` |
| **14** | three candidates #13 left on the table: `Serial`, QR as a type, sealing `RecordData` | **all three done 2026-08-02**, one commit each. 14a removed the second copy of RFC 1982 §3.2 and made `a > b` on two serials a compile error; 14b put all three socket entry points behind one `Request` door; 14c sealed `RecordData` into its own module — and, by asking what invariant it actually holds, found that a legal RFC 2136 UPDATE could not be parsed at all. 14a and 14b are preventative and say so; 14c's finding is under #10, with a regression test watched failing |
| **16** | simplifications: `Nsec3`'s fallibility, splitting `parse_into`, and a duplication that must stay | **16b done, 16a corrected-and-withdrawn, 16c recorded as not-to-fix, 2026-08-02.** 16a is the interesting one: the filed plan did not survive being checked against `nsec3_hash` and is kept struck through with the reasoning, but the pass it came from found a live defect in `proves_no_ds`. Three more defects in `parse_dnssec_time` fell out of the same sweep |
| **15** | collapsing `DName`/`UnpackedDName` into one borrowed, pointer-following `DName` | **withdrawn 2026-08-03**, filed 2026-08-02 and never started. Reviewed against the code rather than the plan: the typestate is already invisible outside `dname.rs`, the volume breaks even, the allocation motive was spent before it was filed, and the price is threading absolute offsets through every parse site — declined. The section keeps the three findings and the two fixes the review *did* produce (the unenforced 255-octet name limit, the LDH `TODO` that would have been a bug) |
| **12** | pre-authentication panics | **audited 2026-08-01.** No reachable panic in 1.4M mutated inputs; two mutex-poisoning fixes; `rdns/tests/no_input_panics.rs` left behind as the guard |
| **13** | making illegal states unrepresentable: `OpCode`'s sentinel, the eleven name normalizations, QTYPE-vs-RTYPE, `Ttl` + `Class` + OPT out of the additional section, `Name`/`NameKey` | **done 2026-08-02**, twelve commits. 13a-13d in full; 13e's map keys done and its `Name` half deferred with a reason. Seven live defects fixed on the way. Every stage gated on `rdns/tests/allocations.rs` and every one has held its counts; 13b added a fifteenth measurement that went 2 to 0 |
| **17** | the TCP length prefix wraps to 0 on a TSIG-signed answer near 64 KB, and the framing is written out five times | **fixed 2026-08-03.** The one confirmed bug of the review — provoked, not argued: a wrapped prefix of 0 is what both read loops treat as a broken peer, so the client's connection is dropped with no answer. `append_tsig` is what pushes a message past the size it was serialized to |
| **18** | `rdnsr` has none of the operational shell — no rate limiter, no response budget, no logger, no metrics, no probes, no validator | **fixed 2026-08-03.** Seven library facilities `rdnsd` uses and `rdnsr` does not, all of them tested and reachable. The asymmetry runs the wrong way round: the resolver is the more amplifying of the two and the unobservable one. Probably #9d being scoped to `rdnsd` |
| **21** | the deviations and the not-implemented list | **an inventory, not a queue**, filed 2026-08-03. Four deliberate deviations (D-1, D-5, D-6, D-7) and eight unimplemented things, each with the decision that produced it. Names the two worth reopening if anything here ever is: D-1's cost is the argument #15 was *not* withdrawn against, and DNAME is the only absence that produces a wrong answer rather than an incomplete one |
| **20** | `rdnsd/src/main.rs` is one file and eleven subsystems | **done 2026-08-03**, one commit per seam: `answer.rs`, `zones.rs`, `replication.rs`. 8,328 → 5,956 lines, every move diffed against `HEAD` to prove it changed nothing. Two corrections to the filed plan, both from measuring what each name drags behind it |
| **19** | the review's smaller items, 19a-19h | **closed 2026-08-03.** Five stragglers of consolidations that caught most copies and missed one (19a-19c, 19h), one duplicated check (19e), one candidate that may not be worth it (19f), and two documentation items (19g and the `#13e` correction below). Includes the list of what the pass checked and found *nothing* wrong with, which is the half of §16 that turned out to be most useful |

**What the letters mean**, because comments in the code and lines further down
this page still name them and the sections they named are gone:

| | |
|---|---|
| **9a** | the answer path missing three of RFC 1034 §4.3.2's four cases — no CNAME chasing, no delegations, one-label wildcards |
| **9b** | wire-input safety: the RDLENGTH slice, the `i32` TTL widened to `u64`, the oversized-datagram kill switch |
| **9c** | error handling that degraded quietly: a broken zone file skipped rather than failing the load, EXPIRE lost across a SIGHUP, a response answered as a question |
| **9d** | the operational shell: flags, log levels, config file, metrics, control socket, graceful shutdown, readiness, container image, the rate limiter's units |
| **9e** | performance: the DHAT pass and everything it found — allocations per query, the criterion harness, and the two items closed by measuring rather than fixing |
| **9f** | smaller conformance gaps: the class check, QTYPE=ANY, unknown QCLASS/RCODE round-tripping, QNAME minimisation's ceiling, `rdnsc` on a non-53 port |

**The three findings on this page that were wrong, kept because the reasoning is
the useful part** (`CLAUDE.md` §11 — correct in place, never quietly):

- *"CI runs all of this now"* (2026-07-30), while `git remote -v` was empty. See
  "Current state"; the cost was `rdnsd` not compiling on Unix for a month.
- *"`enumerate_zone_files` already returns `Ok(empty)` for an empty directory"*,
  which went into a commit message, a doc comment and this file without anyone
  reading the twenty lines that would have settled it. It returned `Err`, and a
  secondary pointed at an empty directory then refused to start.
- *"the profiler is global, so every test now holds the mutex for its whole
  body"* — true and insufficient. A mutex in a test file cannot serialize
  libtest's own bookkeeping on its other threads, which is why
  `rdns/tests/allocations.rs` is one `#[test]` today.

~~**One decision is the copyright holder's, not a bug:** the manifests say
`MIT OR Apache-2.0` and the repository ships only an MIT `LICENSE`. Either add
`LICENSE-APACHE` or narrow the manifests. `cargo deny` passes either way.~~

**Taken 2026-08-04: narrowed to MIT.** `license = "MIT"` in the workspace
manifest, which is the one place it is declared — the five crate manifests all
say `license.workspace = true`.

Checked before changing it, because "can I" is a different question from "should
I":

- **Sole human author** (`git log --format='%an'`), so nobody else's consent is
  in play — and it would not have been anyway: narrowing from `A OR B` to `A`
  takes away no permission anyone previously had, since every past version
  already offered MIT as one of two choices.
- **No copyleft or reciprocal dependency.** 138 third-party crates, all
  permissive; the audit is in the commit. Nothing forces a licence on the
  combined work.
- **No vendored third-party source** — no foreign copyright header or
  `SPDX-License-Identifier` anywhere in the tracked tree, so there is no code
  here carrying obligations of its own.

**What it costs, which is the only thing that changes for a user:** Apache-2.0 §3
grants patent rights expressly and MIT does not. That grant is why the Rust
ecosystem dual-licenses by default, and dropping it is the substance of this
decision rather than a side effect of tidying a manifest.

`deny.toml` is untouched: its allow-list is about what *dependencies* may be
licensed under, which this does not affect.

##### `### Where to pick up next`

**#14 is closed.** All three candidates landed on 2026-08-02, and 14c turned
up a live defect in #10 on the way. ~~Everything here is a choice rather than a
queue — **except #23, which is not.**~~ #23 closed on 2026-08-04, so it is all a
choice again; the numbered order below is age, not priority.

> ~~**0. #23, the NSEC3 cache scan.** Filed 2026-08-04, and the only item on this
> page that a stranger can point at the server. `rdnsr --dnssec-validate` spends
> up to a second of CPU on one query, holding the denial cache's global mutex for
> the whole of it, because the NSEC3 lookup re-hashes the name once per cached
> record instead of once. The map it should be asking is already keyed by the
> hash. Timed, not argued — the numbers and the shape of the regression test are
> in §23.~~ — **fixed the day after it was filed** (`9715c3c`), 1 124 ms → 1.28
> ms. Everything below is a choice again.

> **1. Push, and read the second CI run.** Everything the first one reported is
> fixed locally and unpushed. There were two findings, not three:
>
> - **The Windows `build and test` job failed**
>   `a_reload_does_not_hold_the_write_lock_across_its_diffs`, and the test was
>   wrong rather than the code. Fixed in `8758476`; the reasoning is in "Current
>   state" and in the test's own doc comment.
> - **`actions/checkout@v4` targets Node 20**, which the runner now forces onto
>   Node 24. Bumped to `@v5` across all six jobs in the same commit. This warning
>   appeared in more than one job's log — including `licences and advisories`,
>   which is what that job is *called*; `cargo deny` itself passed. Worth knowing
>   before reading a log: a job name here describes what it checks, not what it
>   complained about.
>
> Five jobs have still never actually been read: msrv (1.95), deny, the container
> image, the `dhat-heap` feature build, and clippy on *Linux* — ~~the Linux
> image has no clippy package, so that half had only ever run on Windows~~
> (**wrong; corrected 2026-08-04 — it has clippy, and the workspace is clean
> under it, `#[cfg(unix)]` half included**). They may have passed silently;
> nobody has looked.
>
> **2. #17, the TCP length prefix** — **the only confirmed bug on this page**,
> and the shortest item on it. A TSIG-signed answer whose serialized form lands
> in an 82-octet window below 64 KB is framed with a prefix of **0**, which both
> daemons' read loops treat as a broken peer: the connection is dropped with no
> answer and nothing saying why. Provoked and watched, so the regression test is
> already written in §17 and has been seen failing. Two boxes — a length check in
> `append_tsig`, and one `rdns::framed` helper replacing five unchecked
> `as u16`s.
>
> **3. #10, dynamic UPDATE (RFC 2136)** — ~~**started, one piece in**, and more
> urgent than it was~~ **— done as of 2026-08-03**, apart from incremental
> re-signing and the journal. The paragraph that was here said "the next piece is
> applying the changes, and it must be designed together with the serial: an
> UPDATE bumps it and so does re-signing (#8), and both then have to survive a
> reload that re-reads a file saying something older." That was the right
> instruction and the answer it produced is in §10 — the two compose rather than
> collide, because `signed_serial` **adds** its time term instead of `max`ing it,
> which is the correction #8 had already taken from PowerDNS's docs. What the
> instruction did *not* anticipate is the thing that actually set the design, and
> it is in §10 under "the finding": the reload it mentions is not only a restart
> or a SIGHUP, it is the **re-signing timer**, which reloads from the file every
> cycle — so persistence was a precondition for dispatch rather than a step after
> it.
>
> **4. #18, `rdnsr`'s operational shell** — seven library facilities that exist,
> are tested, and are wired into one daemon. Staged it is small, and one of the
> four boxes is a *decision* rather than code: which counters a resolver should
> have, since `rdnsd`'s set is authoritative-shaped.
>
> **5. #19, the smaller items** — 19a-19h, none of them large. 19d (three metrics
> nothing increments) and 19h's one-liners are the cheapest; 19e is a
> prerequisite for #18's last box.
>
> **6. #11, cache locality** — wanted, but blocked on hardware counters this
> machine cannot read. Its harness is ready. Note that **#13e deliberately stops
> short of this**: a `Name` with inline or wire-format storage is #11's question,
> and doing both at once means neither measurement can be read.

> **Two corrections to this list, 2026-08-03** (`CLAUDE.md` §11 — in place, not
> quietly). It had **#10 as both item 2 and item 3**, saying much the same thing
> twice with the second one more accurate, and a stray "#14 is closed" repeated
> between them from the paragraph directly above. And **item 4 was "the rest of
> #13 (13b-13e)"**, which went stale on 2026-08-02 when #13 closed in full —
> a queue that outlived the work it described. Both are folded into the list
> above. The pattern is the one the "Open work" preamble just recorded: a
> hand-maintained ordering is a claim that goes stale whenever the sections move,
> and nothing checks it.

---

## What "What is open" said, kept verbatim

`TODO.md`'s "What is open" from the end of its status line onward, moved here on
2026-10-04 when the page was cut down to orientation; only the #21 pointer
stayed behind. "This page", "above" and "below" mean `TODO.md` as it was.

#150-#154 came out of a review on 2026-10-01 asking where a missing
abstraction makes a caller carry state between calls into a module, or
re-derive what the module already knew. Five rows, none a defect on the wire.
#155 was split out of #153 in triage on 2026-10-02, #156 out of #155, #157
was found grilling #156, #158 grilling #157,
and #159 grilling #158.
Checked and not filed: `answer_transfer`'s refusal ladder (#130 already says
why), `rdnsr`'s `(resp, authenticated, why)` triple through `finish` and
`finish_dns64` (inside `handle_query`, which #88 left alone),
`rdnsd/src/zones.rs`'s eight `zone_signer` imports (`ZoneSigning` *is* the
abstraction over them), and `replication.rs`'s nine `secondary` imports
(the `Replica` trait, two implementations). A crate split of `rdns` along
its four clusters was re-checked and stays declined: it would make every
cross-cluster item `pub` that could be `pub(crate)` today.
#138-#146 came out of an idiom and std-reuse review of the whole workspace on
2026-09-28, and all nine closed the same day. The four bugs, #138-#141, were
each provoked before filing; #147, a fifth, came out of probing 145e.
Checked and not filed: a `HashMap` group-by in `replication.rs:708`, which
would make withdrawal order nondeterministic; a `with_capacity` guess in
`journal.rs:62`, where at most 32 deltas are followed by an fsync;
`dnstap.rs:356`'s byte arrays; `security.rs:483`'s untrimmed zones, which
`ZoneScope::of` trims; and `record.rs:185`'s stable sort.
#136 came out of a review asking where injecting a dependency would deepen a
module, and closed the same day with the resolver's exchange behind a seam;
closing it filed #137.
#127-#130 came out of a deepening sweep of the workspace on 2026-09-27: one
defect (#127, closed the same day) and three places where a module's
interface is its callers' problem. Grooming those three found #131 and
#132, both bugs, and both closed the same day; closing #132 found #133,
and closing #133 found #134.
Checked and not filed: the transfer ladder (#130 says why), the `[server]`
keys (#63h's macro), the two UDP loops (#30), the reload seam (#83, #112).
#58, #68 and #107-#136 are closed. #117-#119 came out of a fourth
architecture review on 2026-09-25 and were groomed against the code before
filing; #120 came out of verifying #68, #121 and #122 out of verifying #120,
#123 and #124 out of verifying #122, #125 out of closing #121, and #126 out
of reviewing #125.

**#107 through #115 came out of a third architecture review on 2026-09-21**,
this one asking where a module's interface is nearly as large as what is behind
it and where a test cannot reach past one. Nine rows, none of them a defect on
the wire, and **not one names a costed remedy** (§18) — every row says what was
measured and stops.

What the review did *not* file is the half worth reading. The two UDP loops,
the two clock reads and the per-transport admission differences are #30's "What
must not be unified" and nothing found contradicts it. `rdnsr`'s `handle_query`
at 460 lines is answered by `finish_dns64`'s own header, as #88 already
recorded. `rdns`'s 40 modules were re-checked against the negative result below
and it holds. And #83's `absolute_name` was challenged — "a second spelling is
§7's whole subject" reads oddly for a one-line alias whose two call sites
already reach one implementation in `rdns` — and left alone: it is a name, not a
drift surface, and the row it belongs to is closed.

One row corrects a claim's *scope* rather than a claim: #107 against
`clock.rs:42`. The decision #92 took is right for `rdnsd`; the sentence it
produced is about the whole tree and the count behind it never left that crate.

**#107 closed** on 2026-09-22. Its eleven reads are exact and the crate held fifteen; three of the other four are #92's own category, and the fourth — `validate_rrset`, reached from the UPDATE path — declines for #92's reason, since a test chooses the signature's validity window instead. What the row was really about is fixed: `clock.rs` said of the tree what was true of one crate.

**#111 closed** on 2026-09-22, all five sub-items. 111a fixed the two drifts
the row named — both latent, the cost fixture being `$TTL 3600` over MINIMUM
3600 and its keys one SEP and one ZSK — 111b the drift it did not name, no
`policy.chain` branch at all, and 111c is the guard that runs:
`the_split_builds_what_sign_zone_inner_builds` compares the two zones record for
record under Ed25519, whose signatures are deterministic, and all three drifts
were watched failing it. 111d and 111e are the two worth reading. **111d**: the
guard fails
2 runs in 3 on Linux at 10 000 records and always has, and the cause is that the
whole is timed on its first run at a size while the parts inherit a warm
allocator — 39.2 ms against 31.1 for the same work. Both candidates the filing
named were wrong, and `check_split`'s doc had the mechanism backwards.
The claim that had to be struck was in the *test*, not in the helper the row
quotes. **111e**: the remedy 111d shipped fixed the small end by breaking the
large one — warming only the whole made it 33.2 s against 28.2 at a million
records on Windows, where Linux read 1.015 on the same code. Both sides are
warmed now. A warm-up is a statement about which side you warmed.

**#115 closed** on 2026-09-22, and triage found the row's own correction stale
before it fixed the prose: a field count written from a scan that cannot see
`nsec3`. What shipped drops both counts and cites the test that holds the rule,
because this row is now twice the evidence that a number in prose does not stay
true.

**#108 closed** on 2026-09-24, and the shape question it left open is what
decided the fix: four of the five sites hold a record and the fifth holds the
pair `carry_over_records` split out of one, so the home takes two loose values.
What the row did not name is the larger half — not one of the five had a test
for *both* one-term spellings, and three of the missing cases are the same
`$TTL`-over-MINIMUM fixture #73 hid behind.

**#106 closed** the day it was filed, and it was worse than built-and-
discarded: a zone small enough to fit one envelope *transferred* over DoH, so
whether DoH carried a transfer depended on zone size. Refusing narrows that,
and the narrowing is the finding.
**#105 closed** the day it was filed, and its open design question has an
answer that leaves #30e alone: what #30e argues is that the two *daemons*
disagree, so the parameter and its call sites stay — what became one is the
four *adapters*' reading of it, which is the thing that drifted.
**#104 closed** the day it was filed, and the count in its title is wrong:
there are two maps and a zone list, not four maps, and unifying them is
declined on that measurement. What asking the question found instead is two
defects in the UPDATE path — an `$INCLUDE` resolved against the process's
working directory, and under it a digest that let an edit to an included file
be silently reverted — one of which was hiding the other.
**#103 closed** the day it was filed, and the measurement that could have
refuted it narrowed it instead: `dead_code` does warn about a `[server]` field
nothing reads, so the silent case is the one where something *else* reads it —
`check` reads ten of `rdnsd`'s keys — which is exactly a key that arrives with
a validation rule.
**#100 closed** the day it was filed, and it undercounted itself: the UPDATE
path was the only one with no verification at all, but the *incremental*
signer's output had never been checked on any path, a reload's included. The
fix is the one the row named — the signing call hands back a value whose only
exit is the check — plus the set the row did not name, because verifying what
the signer says it signed agrees with the one bug that path can have (§19).
**#102 closed** the day it was filed, and the remedy it named was the wrong
one: the `From` impl it proposed deleting was never the defect, and the fix is
that the value stops being in flight for 226 lines.
**#101 closed** the day it was filed, and it is #99's shape one file over: a
rule stated in a comment, held by nothing, with the test that locked the
original fix in counting the wrong number.
**#100 through #106 were filed together** out of the same architecture review
that produced #99, each with its quote checked against the file before the row
was written. #105's framing did not survive that check and the row leads with
the correction; none of the seven names a costed remedy (§18).
**#99 filed and closed** out of an architecture review: `--check-config` was a
`return` at a line number in both daemons, and the rule §15 stated turned out to
be wrong in both directions — a dry run moved down to the first spawn would have
deleted journals.
**#98 filed and closed** the day the agent-skill config landed: it pointed at a
`CONTEXT.md` and a `docs/adr/` that do not exist, and what went was the pointer
rather than a glossary being written — the definitions are in the doc comments
and in the RFCs, and a second copy is where drift goes (§7).
**#97 closed** the day it was filed: `licences and advisories` had been red
since 2026-09-12 and the reason it was not noticed is that `cargo deny check`
by hand checks a narrower graph than the job does.
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
default type parameter and zero call sites. **#68 stayed open then** (closed
2026-09-25, see its row) **and both of its guesses are gone**: the
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
by the page's own count, and the record is in `docs/closed/log.md` under "How
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

**#33 closed on 2026-09-06**, its last two items a day after the rest; the
section is `docs/closed/033.md`, where the five
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
`rdnsd`. The section is `docs/closed/034.md`.

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
going stale" in `docs/closed/log.md`, because the shape is the lesson.

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
