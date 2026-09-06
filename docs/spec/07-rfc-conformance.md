# 7. RFC conformance, deviations and gaps

Compiled by reading the code on 2026-08-03 at commit `5506612`, revised the same
day at `262b5f3`, by which point nine commits had closed most of what it
recorded. Closed entries are struck through and kept: what a gap *was* is the
useful half, and a table showing only the present state would lose the reason
each row exists (`CLAUDE.md` §11).

"yes" means implemented *and* covered by a test that names the RFC section;
"partial" means implemented with a stated limit; "no" means absent.

---

## 7.1 Core protocol

| RFC | subject | status | where |
|---|---|---|---|
| 1034 §3.6.2 | one CNAME per owner name | yes — refused at load | `zone::check_cname_exclusivity` |
| 1034 §4.2.1 | delegation, glue | yes — in-bailiwick glue only | `refer_to_child` |
| 1034 §4.3.2 | the four cases, in order | yes | `resolve_in_zone` |
| 1034 §4.3.3 | wildcard answer echoes the queried name | yes | `add_answer` |
| 1035 §2.3.4 | 63-octet label, 255-octet name | yes, both directions | `dname.rs` |
| 1035 §2.3.1 | preferred name syntax (LDH) | **deliberately not enforced** | see D-5 |
| 1035 §3.2.3 / §3.2.5 | QTYPE ⊃ TYPE, QCLASS ⊃ CLASS | yes — separate newtypes | `lib.rs` |
| 1035 §3.3.14 | TXT is a sequence of character-strings | yes | `ParsedRecord::TXT` |
| 1035 §4.1.1 | opcode echoed, AA clear on referral | yes | `make_response`, `refer_to_child` |
| 1035 §4.1.4 | name compression, both directions | yes | `compression.rs`, `dname.rs` |
| 1035 §4.2.1 | 512-octet UDP, TC=1, TCP retry | yes | `to_bytes_within` |
| 1035 §4.2.2 | 2-octet TCP length prefix | yes, checked — **D-2** fixed 2026-08-03 | `rdns::framed`, one site |
| 1035 §5 | master file format | partial — no `$GENERATE` | `zone.rs` |
| 1996 | NOTIFY, both directions | yes — **D-3** and **D-4** both fixed 2026-08-03 | `notify.rs`, `rdnsd` |
| 1982 | serial arithmetic | yes — `Serial` has no `Ord` | `lib.rs` |
| 2181 §8 | TTL is unsigned; top bit set reads as 0 | yes, clamped at the boundary once | `Ttl::from_wire` |
| 2181 §11 | any binary string may be a label | **no** — see **D-1** | `dname.rs:143` |
| 2308 §2 | negative answers carry the SOA | yes | `add_negative` |
| 2308 §3 | negative TTL = min(MINIMUM, SOA TTL) | yes, and the RRSIG beside it | `negative_ttl`, `soa_signatures` |
| 3597 | unknown RR types round-trip | yes, incl. `\#` and `TYPEnnn` | `RecordData`, `zone_writer` |
| 4343 | case folding is ASCII-only | yes — **D-4**'s two exceptions fixed 2026-08-03 | `utils::ascii_lowered` |
| 4592 §2.2.1 | no synthesis at or below a cut | yes | `name_kind_of_key` |
| 4592 §2.2.2 | a name with descendants exists | yes — `non_terminals` | `zone.rs` |
| 4592 §3.3.1/§3.3.2 | synthesis to any depth, closest encloser | yes | `name_kind_of_key` |
| 4592 §4.4 | an existing name ends the search | yes | `name_kind_of_key` |
| 5936 | AXFR: TCP only, SOA-framed, multi-message | yes | `transfer.rs` |
| 1995 | IXFR, both directions, UDP single-SOA form | yes, and the deltas survive a restart since 2026-08-03 | `ixfr.rs`, `journal.rs` |
| 6891 | EDNS0 | yes — one OPT enforced, BADVERS, mirroring | `lib.rs`, `make_response` |
| 6895 §2.3 | the RCODE space stays open | yes — `ResponseCode::Other` | `lib.rs` |
| 6761 / 6762 / 6303 | special-use names | yes (`rdnsr` only) | `special_names.rs` |
| 7766 §6.2.1 | many queries per TCP connection, concurrent | yes | both daemons |
| 8020 | NXDOMAIN cuts the subtree — so AA must be right | yes, and it is why REFUSED is used for zones we do not hold | `make_response` |
| 8482 §4 | ANY answers | yes — `Qtype::matches` | `lib.rs` |
| 8945 | TSIG, incl. signed errors and chained MACs | yes | `tsig.rs` |
| 2136 | dynamic UPDATE | **served end to end** (2026-08-03): §2.4/§2.5 forms, §3.1/§3.1.1, §3.2, §3.3 per-key scoping, §3.4.2, §3.6, §3.7. TSIG-only, scoped per key, persisted before the client is told it succeeded. A signed zone is re-signed incrementally and the version steps are journalled — see **G-4** and `TODO.md` #10 | `update.rs`, `journal.rs`, `rdnsd` |
| 6672 | DNAME | **yes** (2026-09-06): §2.2's substitution incl. Table 1, §2.3's owner-not-redirected, §2.4/§3.3's load refusals, §2.5's uncompressed target, §3.1's synthesized CNAME, §3.2's server algorithm with YXDOMAIN on overflow, §3.4/§3.4.1's resolver half, §5.2's UPDATE rules and §5.3's DNSSEC. Obsoletes 2672 | `utils::dname_redirect`, `Zone::dname_above`, `rdnsd/src/answer.rs`, `resolver.rs` |
| 7858 / 8484 / 9250 | DoT / DoH / DoQ | no | — |
| 7873 | DNS Cookies | opaque round-trip only | `EDNS_OPTION_COOKIE` |
| 2931 | SIG(0) | no | — |
| 9460 | SVCB / HTTPS | opaque only (RFC 3597 path) | — |

## 7.2 DNSSEC

| RFC | subject | status |
|---|---|---|
| 4033–4035 | validation, answer shapes, AD/CD | yes |
| 4034 §3.1 | RRSIG field order (expiration before inception) | yes |
| 4034 §4.1.1 | the NSEC chain is a loop | yes — `nsec_covering` wraps |
| 4034 §6 | canonical form and ordering | yes |
| 4035 §2.2 | a delegation's NS RRset carries no signature | yes |
| 4035 §3.1.1 | DNSSEC types are not ANY data unless DO asked | yes — `Qtype::matches` |
| 4035 §3.1.3 | a wildcard answer denies the queried name | yes |
| 4035 §3.1.4 | a referral carries the DS or its denial | yes |
| 4035 §5.3.2 | wildcard reconstruction from the label count | yes |
| 4035 §5.4 | the proof is about the end of the CNAME chain | yes |
| 5011 | managed anchors, 30-day hold-down, revocation | yes |
| 5155 | NSEC3, closest encloser, opt-out | yes |
| 5155 §7.1 | the bitmap lists every type at the name | yes |
| 5155 §8.1 | ignore unknown NSEC3 hash types (whole-set) | yes |
| 5702 | RSA/SHA-256, RSA/SHA-512 | verify + import; **no generation** (`ring`) |
| 6605 | ECDSA P-256, P-384 | yes, generate and verify |
| 8080 | Ed25519 | yes, generate and verify |
| 8198 | aggressive use of validated denials | yes, both halves |
| 8624 §3.1 | RSA/SHA-1 NOT RECOMMENDED | accepted for **verification** only, deliberately |
| 9276 §3.1 | empty NSEC3 salt, zero iterations | yes, and signing above the cap is refused |
| 9156 §2.3 | QNAME minimisation, QTYPE=A, cap 10 | yes |
| 4470 | white lies / minimally-covering NSEC | no — the chain is precomputed |
| 6781 | key-rollover *automation* | no — rollover is manual; the signer will not delete a published DNSKEY |

## 7.3 Deviations

Behaviour a reading of the cited RFC would not predict. Each is deliberate unless
marked otherwise.

### D-1 — a label that is not valid UTF-8 is refused

`dname.rs:143`. RFC 2181 §11: "any binary string whatever can be used as the
label of any resource record". This implementation rejects such a label with
`WireError::Malformed`, which a daemon answers FORMERR.

Deliberate, and the trade is stated in `dname.rs`: names are `String`s in
presentation form throughout, and the alternative is a different representation
(labels or wire bytes) — a change `TODO.md` #13e scopes and defers, and which
`TODO.md` #21 records as the one deviation with a cost worth reopening for.
Consequence: a zone containing such a name cannot be served, and a response
containing one is unparseable, so a resolver cannot relay it.

### D-2 — the TCP length prefix is an unchecked cast — **fixed 2026-08-03**

~~Five writers compute the 2-octet prefix as `bytes.len() as u16` with no check,
so a message longer than 65,535 octets is framed with a wrapped length. At
exactly 65,536 the prefix is **0**, which both daemons' read loops treat as a
broken peer.~~

Fixed in `ad5ed65` (`TODO.md` #17). `rdns::framed` is the one writer and returns
`WireError::TooLong` rather than casting; `tsig::append_tsig` — the only path
that can grow a message past the size it was serialized to — refuses rather than
producing something no framing can express. The regression test is the sweep that
found it, and was watched failing at the size it originally reported: 65,536
octets.

### D-3 — NOTIFY transaction ids are not random — **fixed 2026-08-03**

~~`subsec_nanos()` XOR-folded to 16 bits, where `xfr::rand_id` for the same
purpose uses `rand::thread_rng()`. Two NOTIFYs in the same clock tick share an
id. The stated reason — "a full CSPRNG is overkill for a message we also match by
source and opcode, and the workspace's `rand` is a library dependency rather than
this crate's" — holds for the threat but leaves two functions of the same name
with different security properties.~~

There is one `utils::rand_id` now and both call it. The dependency argument was
what made the second copy look reasonable, and it is exactly what exposing the
first one removes: `rdns` already has `rand`, so `rdnsd` needs no new dependency
to stop having its own. An id is still not a security boundary here — a NOTIFY is
matched by source address and opcode too — but that is a reason to keep it cheap
rather than a reason to make it predictable.

### D-4 — two live `str::to_lowercase` calls on names — **fixed 2026-08-03**

~~The NOTIFY zone-name lookup key (attacker-supplied) and the matching insert.
`CLAUDE.md` §8 and RFC 4343 require ASCII-only folding; `to_lowercase` folds
U+212A KELVIN SIGN onto `k`, so a NOTIFY naming a Kelvin-sign variant of a
replicated zone folded onto that zone.~~

Fixed in `262b5f3` (`TODO.md` #19a). Both sites, and the replicated-zone check
the dynamic-UPDATE path added the same day, now go through
`utils::absolute_lowered`, so all three agree by construction rather than by
having been written to match.

### D-5 — LDH label syntax is not enforced

RFC 1035 §2.3.1's "preferred name syntax" is advice to whoever *chooses* a
hostname, not a rule about what the protocol carries; RFC 2181 §11 settles it.
Enforcing it would refuse `_dmarc`, every `_tcp` SRV owner, DNS-SD instance names
and the wildcard `*` itself. Deliberate, and documented in place.

### D-6 — the first compression pointer in a chain may point forward

`dname.rs:384`. Every *subsequent* pointer must strictly decrease, which is what
makes cycles unreachable; the first is unconstrained because a name is parsed
from a suffix slice that does not know its own offset. Deliberate, with the
reasoning and the cost of the alternative written in place. Termination is
unaffected.

### D-7 — class CH and HS are refused rather than served

`Class::CH` and `Class::HS` exist as types, the zone parser refuses a non-IN
record, and a non-IN question is REFUSED. So `version.bind CH TXT` — which BIND,
NSD and Knot all answer — is not answered. Deliberate: RFC 1034 §4.3.2 step 1
searches the zones of the question's class, and holding none is the same as
holding no zone.

## 7.4 Gaps

Things that are absent rather than different, and that the code's own rules
suggest should not be.

### G-1 — `rdnsr` has none of the operational shell — **fixed 2026-08-03**

~~`rdnsd` uses `security::RateLimiter`, `security::ResponseLimiter`,
`logging::QueryLogger`, `metrics::DnsMetrics`, `metrics_server`,
`validation::RequestValidator` and `readiness::Readiness`. `rdnsr` uses none of
them, and is the more amplifying of the two daemons.~~

Fixed in `ad5ed65` (`TODO.md` #18). `rdnsr` gained `--query-rate`,
`--query-burst`, `--query-rate-exempt`, `--response-rate` and
`--metrics-listen`, all through the same library types and the same
`RateLimitConfig::per_second` units. The query-rate default is 200 against
`rdnsd`'s 1000, because a resolver's clients are end users where an authoritative
server's are resolvers.

### G-2 — `rdnsr` runs no `RequestValidator` — **fixed 2026-08-03**

~~A request over the UDP size cap, or with absurd section counts, reaches the
parser rather than being refused before it.~~

Fixed in `ad5ed65`, and the decision was made out loud as `TODO.md` #18 asked.
The check is wired in on the pre-admission path, after the rate limit and before
the in-flight semaphore. The type is now called `AdmissionCheck`, because after
`262b5f3` (#19e) that is what it is: size and section-count caps, and no longer a
second, weaker copy of the parser's name rules.

### G-3 — three metrics are exported and never incremented — **fixed 2026-08-03**

~~`dns_cache_hits_total`, `dns_cache_misses_total` and
`dns_queries_recursive_total`. `DnsMetrics` is used only by `rdnsd`, which has no
cache and never recurses, so a dashboard computing a hit rate gets 0/0.~~

Fixed in `ad5ed65` (`TODO.md` #19d), by the second of the two routes that item
offered: they moved rather than being deleted, because nothing about them was
wrong — they were in a binary with no cache. `rdnsr` counts `cache_hits` on each
of its three cache paths and `cache_misses` with `queries_recursive` where a
query falls through to an actual recursion. `queries_authoritative` is now the
counter with no home there, and is deliberately never touched.

### G-4 — RFC 2136 is implemented and unreachable — **closed 2026-08-03**

~~`rdns/src/update.rs` — 1 070 lines, fully tested — parses an UPDATE, checks its
prerequisites against a zone and stops. **No binary references it**; `rdnsd`
answers NOTIMP for opcode UPDATE.~~

The gap was real when it was written and was closed the same day by `fedf8d9`,
`fedf8d9` and `fedf8d9`: `rdnsd` now answers opcode UPDATE on both transports,
authorized per key, applied, persisted to the zone file and served. See
`TODO.md` #10.

The observation that produced this row is worth keeping even though the row is
closed, because it generalizes past this feature: a library that carries a
tested, unreachable feature has a test suite that cannot tell it from a working
one. That is `CLAUDE.md` §1 at module scale, and it is exactly how the
RDLENGTH=0 defect (`eff4fcb`) survived — every test in `update.rs` built its
message in memory, so the one boundary a real UPDATE crosses was the one nothing
exercised. The end-to-end tests added with the dispatch cross it deliberately.

### G-5 — the metrics listener has no connection ceiling — **fixed 2026-08-03**

~~`metrics_server::serve` spawns a task per accepted connection with no
semaphore, unlike `rdnsd`'s and `rdnsr`'s DNS TCP loops. The only accept loop in
the workspace without a bound.~~

Fixed in `262b5f3` (`TODO.md` #19h). Bounded at 16, and `try_acquire` rather than
`acquire`: a scrape that has to queue is one whose sample is stale by the time it
is served, so closing the socket — which a collector reads as a failed scrape — is
the honest answer.

---

## 7.5 How to re-check any row

- Against another implementation: dnspython is the reference used throughout
  `TODO.md`; the four environment traps that make a comparison lie are recorded
  there under "Verifying".
- Against ourselves: a signed answer is judged with `verify_rrset`,
  `proves_nxdomain` and `proves_nodata` — the same code that judges a real zone
  off the internet. Our parser agreeing with our serializer proves nothing
  (`CLAUDE.md` §1).
- A new regression test must be shown to fail against the old behaviour. Revert
  the fix, run the test, watch it fail, put the fix back.
