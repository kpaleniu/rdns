# rdns — TODO / Next Steps

Working notes for picking this up cold. **`CLAUDE.md` is the companion to this
file**: this one says what is left to do, that one says which mistakes this
codebase has already made and the rules that follow from them. Read both before
planning; the first rule in `CLAUDE.md` is why a green suite here has twice not
meant what it looked like.

"Open work" is what is left; the
"Architecture" sections describe what exists and why it is shaped that way.
Completed work is one line each under "Done so far" — the reasoning, RFC
citations and verification for each piece are in its commit message, which is
where to look rather than here.

---

## Current state (last updated 2026-07-28)

**Workspace** — four members, all on branch `master`:

| crate   | what it is                                                        |
|---------|-------------------------------------------------------------------|
| `rdns`  | the library: wire codec, zones, cache, resolver, DNSSEC           |
| `rdnsc` | command-line query client                                         |
| `rdnsd` | authoritative server — serves zone files over UDP and TCP in one process |
| `rdnsr` | recursive resolver with a caching layer; forwards on `--upstream` |

**Green as of the last commit:** `cargo build --workspace` clean,
`cargo test --workspace` = **567 lib + 60 `rdnsd` + 2 `rdnsr`** tests passing
(`rdnsd`'s own 60 cover argument validation, zone sources and the load policy,
the secondary role and EXPIRE across reloads, both directions of IXFR and onward
announcement, answering a DO-bit query from a zone it signed itself, and all four
cases of RFC 1034 §4.3.2; `rdnsr` had **no test module at all** until #9c gave it
one), `cargo clippy --workspace --all-targets` **clean, no exceptions**. The lib
count fell from 578 when dead `serialization.rs` was deleted with its 11 tests.

**Errors are typed in the library and `anyhow` in the binaries (2026-07-28).**
The convention used to run the other way round — `rdns` returned `anyhow::Error`,
which erases the failure kind from its own API, while `rdnsd` and `rdnsr` used
`Box<dyn Error>` and `Result<_, String>` and never called the `anyhow` they both
declared as a dependency. `rdns::error` now holds six types (`WireError`,
`ZoneError`, `DnssecError`, `TransferError`, `ResolveError`, `ConfigError`) whose
variants are the decisions a caller actually makes: truncated is FORMERR and
unsupported is NOTIMP, a bogus signature is SERVFAIL and an unknown algorithm is
insecure, a transfer timeout is retried and a malformed one is not. See
`CLAUDE.md` §3; the reasoning is in the five commits.

**Green did not mean conformant, and the fix for that is `CLAUDE.md`.** The suite
passed at 590 tests while `rdnsd` could not serve a CNAME, a delegation or a
two-label wildcard, because the tests were written from the same understanding as
the code — two of them asserted the wrong behaviour and cited an RFC section that
says nothing about the subject. That is now the first rule in `CLAUDE.md`: assert
what the RFC says and cite the section that says it, use the RFC's own worked
example, and show a new regression test failing against the old behaviour before
landing it. Every fix below was checked that way.

**`rdnsd` serves an ordinary zone correctly now: #9a, #9b and #9c are closed.**
CNAME chasing, referrals at a delegation with AA clear, wildcard synthesis to any
depth, empty non-terminals as NODATA, the apex NSEC3 bitmap, and RFC 2308's
negative TTL cap — plus the remote panic, the negative-TTL cache pin, the
oversized-datagram process kill, the unbounded per-IP tables and the wall-clock
underflows — plus, from #9c, a broken zone file failing the load instead of being
skipped, EXPIRE surviving a SIGHUP, neither daemon answering a *response* or a
non-QUERY opcode, and a CNAME-terminated negative answer having its denial
checked rather than being handed out with AD set. What is left under #9 is
operability (9d), performance (9e) and smaller conformance gaps (9f): real work,
none of it blocking correct service.

**One fix in #9c was a fix to a previous fix.** Closing "an unreadable zone
directory silently unloads every zone" (2026-07-27) also broke a secondary's
first start, because the commit asserted a property of `enumerate_zone_files` —
that it returns `Ok(empty)` for an empty directory — that was simply not true of
the code. The claim went into a commit message, a doc comment and this file
unchecked, and no test covered the case. It is written up under #9c rather than
edited away; see also `CLAUDE.md` §4.

**Steps 1–5 of #7 are done: `rdnsd` replicates in both directions, incrementally
at both ends, and cascades.** It transfers a zone from a master, serves it, writes
it down, refreshes it on the zone's own timers, acts on a NOTIFY *and sends one
onward*, withdraws a zone past EXPIRE, answers an IXFR with just the difference,
and takes one. Verified as a three-node tree where a change at the primary reaches
the bottom in seconds rather than at the next refresh. See "Architecture: the secondary role" and "Architecture:
incremental transfer".

**Only step 6 is left under #7, and it is explicitly conditional** — persisted
deltas matter when dynamic UPDATE (RFC 2136) arrives and not before, because that
is what makes a journal the source of truth rather than a cache of one. **RFC 2136
itself has no entry anywhere and never did** — it appears in this file and in
`ixfr.rs` only as the reason for deferring the journal. That circularity is
written down now as #10; it is not scheduled, but it is at least visible.

**`rdnsd` signs zones now, and #2 is closed with it.** It generates its own keys,
signs every zone it holds keys for as that zone loads, and answers a DO-bit query
with the signatures and the denials that go with it — including the two an
answer *owes* rather than merely carries: a wildcard answer with a denial of the
name asked for, and an NXDOMAIN with a denial of the wildcard that could have
answered it. Verified against **dnspython**, which validated every RRset it was
served under both NSEC and NSEC3. See "Architecture: signing a zone".
`dnssec_validation_mode` is called at last: every signature in a zone is checked
against the zone's own keys before anything is served from it, and `--require-signed`
turns "this zone is not signed" into a refusal to start.

**What is open now is what signing turned up**, listed under #8: no resigning
timer (signatures are made at load, so a server up longer than
`--signature-validity` serves expired ones), no serial bump when a zone is
re-signed, and `rdnsd` answering NXDOMAIN where a referral belongs — the last of
which predates all of this and is not a DNSSEC bug. Plus #1's two aggressive-use
extensions, and #6, a candidate rather than a plan.

**A five-way code review (2026-07-27) found rather more, and #9a/#9b are the part
that is now fixed (2026-07-28).** The headline was that the *answer path* was
missing three of the four cases in RFC 1034 §4.3.2: no CNAME chasing, no referral
at a delegation (#8's third bullet, confirmed and worse than recorded — the
NXDOMAIN went out with AA=1), and wildcard synthesis reaching exactly one label
instead of walking to the closest encloser. On a signed zone the wildcard bug
failed *closed*, so a signed zone with a wildcard SERVFAILed at every validator
for every non-existent name two or more labels deep. There was also an
unauthenticated remote panic in the wire parser (RDLENGTH sliced without a bounds
check). All of that is closed with regression tests that fail against the old
behaviour. The cryptographic and protocol-state work — DNSSEC verification, TSIG,
NSEC3 iteration caps, RFC 5011, serial arithmetic — came through clean; see #9's
preamble for the full list of what was cleared.

**Two claims made further down this file were wrong, and #9 corrects them.** They
are left in place with pointers rather than quietly edited, because the reasoning
that produced them is the interesting part:

- The wildcard rule that used to be cited at `zone.rs:319`, `dnssec_answer.rs:369`
  and in "Architecture: aggressive use" below — *"a wildcard covers one label and
  only one (RFC 4592 §2.1.1)"* — is a **misreading**. §2.1.1 is about `*` being
  special only as the leftmost label in zone-file *syntax*; §3.3.2's worked
  example synthesizes two labels down. Two tests (`zone.rs:1251`, `:1287`)
  asserted the wrong behaviour and cited the same misreading, so **fixing the code
  meant fixing those tests** — a green suite was not evidence here. The code
  comments and both tests are corrected as of 2026-07-28; the "Architecture:
  aggressive use" paragraph below still says it, and is marked there.
- The flaky-benchmark note below blames competing load. It was not: `log_query`
  is O(queries-in-window) per query (`logging.rs:80`), measured at 469 ns → 19.4 µs
  as the window fills, which caps the whole server at ~23k qps. Lowering the
  floor from 45k to 10k ratified a real regression the benchmark had caught. See
  #9e.

**The flaky test is fixed.** `bench::bench_logger_throughput` asserted
`>45k ops/sec` against a measurement of 47–50k, so any competing load failed the
suite; the floor is 10k now, which still catches an order-of-magnitude
regression. (**Superseded — see #9e**: the measurement was falling because of a
quadratic in `log_query`, not because of competing load. Fix the quadratic and
the floor should go back up.) The other benches keep their floors —
`bench_zone_lookup`'s is a factor of ten under what it measures, which is the
rule to follow when adding one. A wall-clock assertion with no headroom is a coin
toss, not a test.

### How to run

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets

# Authoritative server, UDP and TCP from one process. The zone origin comes from
# the FILENAME: example.com.zone serves example.com — a mismatch silently yields
# NXDOMAIN for everything.
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

**Check first whether the network hijacks port 53.** Send any DNS query to
`192.0.2.1` — TEST-NET-1, reserved for documentation, which cannot host a
server. If something answers, every outbound port-53 query on this machine is
being intercepted and answered by a middlebox:

```sh
python -c "import socket;s=socket.socket(2,2);s.settimeout(3);s.sendto(bytes.fromhex('424201000001000000000000') + b'\x07example\x03com\x00\x00\x01\x00\x01',('192.0.2.1',53));print('INTERCEPTED:',len(s.recv(512)),'bytes')"
```

That is the case on the machine this was developed on, and it has two
consequences worth knowing before trusting any measurement in this repo:

- **Recursion cannot be verified here.** Iterative (RD=0) queries to the real
  root addresses get SERVFAIL from the interceptor, so `rdnsr`'s default mode
  fails while forwarding works — the interceptor answers RD=1 happily.
- **`--upstream 8.8.8.8` means "whatever answers port 53"**, not Google. Every
  figure recorded here that involved a public resolver was really measured
  against the interceptor.

For local verification, `nslookup` is unreliable against a non-53 port on
Windows — it reports "No response from server" even when the server replied.
Probe with a raw `System.Net.Sockets.UdpClient` in PowerShell and read the
bytes; that is how the "verified live" claims here were checked.

For an *independent* decode check — our parser agreeing with our serializer
proves little — Node's resolver is c-ares and takes a port in the server string:

```js
const r = new (require('dns').Resolver)();
r.setServers(['127.0.0.1:15353']);
r.resolve4('www.example.com', console.log);
```

**dnspython is installed on this machine** (2.8.0, `pip install dnspython`) and is
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

The numbers are **stable identifiers, not reading order.** They are referenced
from the code (`ixfr.rs:16` points at "#7 step 6") and from each other, so they
are never renumbered — sections get moved instead. Everything still open is
below, roughly in the order worth doing it; closed sections keep their reasoning
under "Closed work" further down.

| # | what | open |
|---|------|------|
| **9** | what the five-way code review turned up | **32** — 9a, 9b and 9c are closed; what is left is operability, performance and small conformance gaps |
| **8** | what signing turned up | **2** — both about re-signing a running server |
| **7** | the secondary role | **1**, and conditional |
| **10** | dynamic UPDATE (RFC 2136) | **0** — not scheduled, listed so the dependency is visible |
| **5** | smaller open items | **0** |

### 9. What a five-way code review turned up (2026-07-27)

A review of the whole workspace from five angles at once — security, Rust,
low-level/wire, DNS protocol conformance, and operating it. Everything below was
confirmed by reading the code or by running it; where a claim was checked by
execution it says so. Ordered by what to fix first, which is **not** the order of
severity: #9a is what stops this being a correct authoritative server at all.

**What the review cleared**, because it says where effort does *not* need to go:
DNSSEC signature verification has no bypass path, DS→DNSKEY binding is by digest,
TSIG MACs are constant-time (`ring::hmac::verify`), checked before any state
change, reject truncation, and cannot be algorithm-downgraded; NSEC3 iterations
are capped per RFC 9276 (the CVE-2023-50868 class is closed); the resolver's
spoofing entropy is sound (per-query random id, fresh ephemeral socket,
`connect()` filtering, 0x20 on by default); compression pointers are
cycle-detected and depth-capped; RRSIG label counting, the extended-RCODE split,
NSEC3 opt-out semantics, RFC 1982 serial arithmetic, AXFR SOA bracketing and
IXFR's fallback detection are all correct. Clippy is clean workspace-wide.

The pattern worth carrying into the fixes: **the hard cryptographic and
protocol-state work is right; the plain-DNS answer path and the operational shell
are where it breaks.** The bugs cluster where the problem looked too simple to get
wrong.

#### 9a. The answer path is missing three of RFC 1034 §4.3.2's four cases

**All six are done, 2026-07-28.** `rdnsd` walks the four cases of RFC 1034 §4.3.2
in the order the RFC gives them — `resolve_in_zone` returns one of referral,
answer, negative, or chain-left-zone, and `make_response` renders each. `Zone`
gained the two lookups the walk needs and did not have: a closest-encloser walk
shared by `query` and `name_exists`, and a `delegation_for` that says where the
zone's authority stops. Verified with 14 new tests in `rdnsd` (`mod answer_path`,
plus three signed ones) and 5 in `zone.rs`; the signed side is judged with
`verify_rrset`, `proves_wildcard_expansion`, `proves_no_ds` and `proves_nodata`
rather than by inspection. Each original finding follows, since the analysis is
what makes the fix reviewable.

**Verified live against dnspython, under NSEC and NSEC3, 2026-07-28** — the whole
point being that our parser agreeing with our serializer proves nothing. dnspython
validated the CNAME chain RRset by RRset, the secure referral's DS, the insecure
referral's signed denial of DS, the three-label wildcard answer (RRSIG label count
lower than the name's, with the denial of the queried name beside it), the NODATA
proof at an empty non-terminal, and the two-denial NXDOMAIN; it also confirmed
AA=0 on both referrals, no RRSIG on either delegation's NS RRset, in-bailiwick
glue only, SOA TTL 300 rather than 3600, and — on the NSEC3 zone — that
`example.com. NSEC3PARAM` now returns the signed record instead of a signed NODATA
proof for a type that is present. The probe scripts were session-local; the recipe
is in "Verifying, and one trap that invalidates it" above.

**Two tests had to be deleted or inverted to land this, which is the finding
inside the finding.** `zone.rs:1251` and `:1287` asserted the one-label rule and
cited the misreading; they are now `test_a_wildcard_synthesizes_at_any_depth` and
an inverted assertion, both citing RFC 4592 §3.3.2's worked example. The whole
suite was green while the server could not serve a CNAME, a delegation or a
two-label wildcard. See `CLAUDE.md` §1.

- [x] **No CNAME chasing** — **done.** `resolve_in_zone` follows the alias while
      it stays in the zone and stops with the partial chain and NOERROR when it
      leaves, bounded by a visited set and `MAX_CNAME_HOPS`. A CNAME *query* is
      answered by the CNAME rather than followed. RFC 1034 §3.6.2 is enforced at
      load: `zone::check_cname_exclusivity` refuses a CNAME sharing its owner
      with anything but RRSIG/NSEC/NSEC3 (RFC 4035 §2.5), because there is no
      correct answer for that shape and two servers reading the same file would
      pick differently. Original finding: (`zone.rs:238`, `rdnsd/src/main.rs:290`). `of_type`
      filters strictly on `record_type_code(&r.rdata) == qtype`, and
      `make_response` branches only records-or-negative. A zone holding
      `www IN CNAME host.example.com.` answers `www.example.com. A` with an empty
      NOERROR + SOA — the wire encoding of "this name has no A record". Every
      CNAME in every zone this server loads is dead: `getaddrinfo` fails, and
      BIND/Unbound cache the NODATA and never follow the alias. RFC 1034 §4.3.2
      step 3a: copy the CNAME into the answer, change QNAME to the target, and go
      back to step 1. Loop while the chain stays in this zone; if it leaves,
      stop with NOERROR and the partial chain — **not** NXDOMAIN. While here,
      enforce RFC 1034 §3.6.2 at load: a CNAME must be the only type at its owner
      (except RRSIG/NSEC/NSEC3, RFC 4035 §2.5).
- [x] **No delegation handling** — **done**, and with it #8's third bullet.
      `Zone::delegation_for` finds the deepest non-apex NS RRset at or above the
      qname; `refer_to_child` emits `authoritive = false`, the NS RRset in
      authority, in-bailiwick glue only in additional, and — with DO —
      `dnssec_answer::delegation_proof`, which is the DS with its RRSIG or the
      signed denial that there is one (including the opt-out closest-encloser
      pair). A DS query *at* the cut is answered authoritatively from the parent.
      No SOA: a referral is not a negative answer. Original finding:
      `response.authoritive` is hardcoded `true`
      at `rdnsd/src/main.rs:203` and cleared only for REFUSED/NOTIMP, so the
      NXDOMAIN goes out with **AA=1**. Per RFC 8020 every resolver then caches
      "the whole subtree does not exist" and the child zone is off the internet
      for the negative TTL. RFC 1035 §4.1.1 requires AA **clear** on a referral.
      Fix with #8's bullet: walk from the qname up to (not including) the apex for
      an NS RRset; if found, emit `authoritive=false`, the NS RRset in authority,
      in-bailiwick glue in additional, and — with DO — the DS + RRSIG or the
      NSEC/NSEC3 denying DS (RFC 4035 §3.1.4). A DS query *at* the cut is the
      exception: answer it authoritatively from the parent.
- [x] **Wildcard synthesis reaches exactly one label** — **done.**
      `Zone::name_kind` walks up to the closest encloser and synthesizes from
      `*.<encloser>` and only from there (RFC 4592 §3.3.1); an existing name,
      empty non-terminal included, ends the search (§4.4); a delegation between
      the encloser and the apex means no synthesis at all (§2.2.1). The result is
      a three-way `NameKind` rather than a bool, because `negative_proof` needs to
      know *which* wildcard matched in order to prove anything about it —
      recomputing it as "first label replaced by `*`" was the second half of this
      bug. The signed case is the regression test that matters:
      `a_deep_wildcard_answer_verifies_and_proves_its_own_expansion` fails closed
      against the old code under both chains. Original finding: (`zone.rs:324`).
      `wildcard_for` is a single `split_once('.')` with `*` prepended. RFC 4592
      §3.3.2's worked example synthesizes `_telnet._tcp.host1.example.` from
      `*.example.` — two labels down. Confirmed by running it: with `* IN A` at
      the apex, `query("a.b.example.com.", A)` returns 0 records where the RFC
      says 1, and `name_exists` says false where it must say true.

      **On a signed zone this fails closed, which is worse.**
      `dnssec_answer::wildcard_denial` computes the closest encloser correctly,
      then asks `nsec_covering("*.example.com.")` — but that name is itself in the
      chain, so the strictly-less-than range lookup returns the record *before* it
      and nothing covers it. Confirmed: the prover returns `NotProved` for both
      NSEC and NSEC3. So **a signed zone with a wildcard SERVFAILs at every
      validator for every non-existent name two or more labels deep.**

      The fix is a closest-encloser walk shared by `query` and `name_exists`:
      find the deepest existing ancestor, and if `*.<that>` exists and the qname
      does not, synthesize from it. Add RFC 4592 §2.2.1 (no synthesis at or below
      a delegation — `zone_signer::Layout` already computes `is_delegation` and
      `occluded`) and §4.4 (an existing name, including an empty non-terminal,
      stops the search).

      **Three comments and two tests encode the wrong rule and must change with
      the code**, or the next reader re-derives the bug from them: `zone.rs:319`,
      `dnssec_answer.rs:369` and the "Architecture: aggressive use" section below
      all cite *"a wildcard covers one label and only one (RFC 4592 §2.1.1)"*.
      §2.1.1 is about `*` being special only as the **leftmost label in zone-file
      syntax**; it says nothing about how deep synthesis reaches. The tests at
      `zone.rs:1251` and `zone.rs:1287` assert the current wrong behaviour and
      cite the same misreading. `zone_signer.rs:934`'s assertion is correct but
      its *reason* is wrong — `x.a.b.example.com.` is NXDOMAIN because
      `a.b.example.com.` is an empty non-terminal, so the closest encloser is
      deeper than the apex; that test will still pass, and its comment will still
      mislead.
- [x] **Empty non-terminals answer NXDOMAIN instead of NODATA** — **done.**
      `Zone` keeps a `non_terminals` set: every ancestor, up to the apex, of a
      name that is in the index, maintained as records are added and rebuilt by
      `reindex`. Insertion stops at the first ancestor already present, because
      ancestors are always noted all the way to the apex — so index construction
      stays linear in the zone rather than names × labels. `holds_name` is
      untouched: the denial path needs the literal question, and `NameKind`
      distinguishes `EmptyNonTerminal` from `Exact` so `negative_proof` can point
      at the record the signer already puts in the chain for it. Original finding:
      (`zone.rs:227`).
      `name_exists` is bare index membership, so with `deep.a.b IN TXT "x"` in the
      zone both `b.example.com.` and `a.b.example.com.` report false. RFC 4592
      §2.2.2: a name with descendants but no records of its own *exists*. An
      RFC 8020 resolver caches the NXDOMAIN and extends it to `deep.a.b`, so the
      zone takes **its own data** offline. Signed, it is self-contradicting: the
      signer does put ENTs in the chain (`zone_signer.rs:413`), so the authority
      section carries an NSEC that *matches* the name while the header says
      NXDOMAIN — and `zone_signer.rs:900` already has a test asserting the proof
      is wrong. Fix: make `name_exists` (or a new `node_exists`) return true when
      any indexed name is a strict descendant; a sorted name index makes it
      O(log n). Keep `holds_name` as-is — the denial path correctly needs the
      literal test.
- [x] **The apex NSEC3 type bitmap omits NSEC3PARAM** — **done.** The record is
      added before `Layout::of` takes its snapshot rather than after the chain is
      built, which is a one-line move and the whole fix. Two tests: one naming the
      apex and NSEC3PARAM specifically, and one asserting over *every* name in the
      zone under both chains that the denial record describing it lists every type
      present at it — because "a record was added after the layout was taken" is a
      class, not an instance, and it can happen at any name. Both fail against the
      old ordering (checked by reverting it). Original finding:
      (`zone_signer.rs:166`).
      `sign_zone` snapshots `Layout::of` at `:166`, builds the NSEC3 chain from
      that snapshot at `:176`, and only *then* adds the NSEC3PARAM record at
      `:177` — so the apex NSEC3 never lists the type. Confirmed by running it:
      `apex NSEC3: SOA=true NS=true DNSKEY=true RRSIG=true NSEC3PARAM=false`,
      with one NSEC3PARAM record actually present at the apex. RFC 5155 §7.1: the
      bitmap of every NSEC3 "MUST indicate the presence of all types present at
      the original owner name", and §4 puts NSEC3PARAM at the apex.
      `dnssec-verify`, `ldns-verify-zone` and `validns` all reject the zone.

      Worse than a lint failure: a validator asking `example.com. NSEC3PARAM`
      with DO gets a signed NODATA proof for a type that **is** present and
      signed — and an RFC 8198 aggressive-NSEC resolver will then synthesize that
      false NODATA for other clients out of its cache. This repo's own `rdnsr`
      does exactly that (`rdnsr/src/main.rs:773`), so we would poison ourselves.
      Fix: add NSEC3PARAM to `signed` before `Layout::of`, or move `Layout::of`
      after the chain-type branch. A regression test asserting the apex bitmap
      lists every type actually at the apex catches the whole class.
- [x] **The SOA in a negative answer is sent with its own TTL, uncapped by
      MINIMUM** — **done.** `rdnsd::negative_ttl` caps it, and
      `dnssec_answer::soa_signatures` caps the RRSIG beside it the same way, so
      the two records in one section no longer disagree about how long the "no" is
      good for. An apex SOA that will not parse yields 0 — the client asks again
      rather than caching a "no" we cannot bound. Original finding:
      (`rdnsd/src/main.rs:313`). RFC 2308 §3: the TTL is
      `min(SOA MINIMUM, the SOA record's own TTL)`. The code pushes `soa.ttl`
      verbatim, so for the zone shape used throughout this repo's own tests
      (`$TTL 3600`, `minimum 300`) every NXDOMAIN and NODATA is advertised at
      **3600 where the RFC says 300** — cached 12× longer than the operator asked,
      so a record added to fix a typo takes an hour to appear. It is also
      internally inconsistent: the signer already uses `minimum` for the
      NSEC/NSEC3 TTL (`zone_signer.rs:168`), so the SOA and the proof beside it in
      the same section disagree about how long the "no" is good for. Same cap
      belongs on the RRSIG TTL in `dnssec_answer::soa_signatures`.
      `NegativeCache` already gets this right — see "Architecture: what `rdnsr`
      remembers"; this is `rdnsd` disagreeing with our own resolver.

#### 9b. Remote crash and unbounded memory

- [x] **RDLENGTH is sliced without a bounds check — remote panic, pre-auth**
      — **done 2026-07-27.** `rdns/src/lib.rs` now checks the declared length
      against the remaining buffer and errors, then `split_at`s; the companion
      re-slice is gone with it. Three regression tests in `lib.rs`'s test module
      pin it: the answer-section shape, the additional-section OPT shape (the one
      that gets past `RequestValidator`), and the boundary case where RDATA ends
      exactly at the message end, which is where an off-by-one in the new check
      would live. Original finding follows, since the reachability analysis is
      worth keeping.

      (`rdns/src/lib.rs:829`, and the companion re-slice at `:839`). Three of the
      five reviewers found this independently.

      ```rust
      let (rdatalen, rest) = read_be!(u16, rest);
      let rdata = &rest[..rdatalen as usize];   // nothing checks this
      ```

      Every other length in the parser is checked — `read_be!`,
      `Label::try_from_bytes`, `parse_options`. This one is not. Confirmed by
      execution, and the nastiest shape passes our own validator: a **well-formed
      QUERY** whose additional-section OPT declares `RDLEN=0xFFFF` with no data
      gets through `RequestValidator::validate_packet` (the additional section is
      where OPT and TSIG legitimately live, so it is only count-capped) and then
      panics with `range end index 65535 out of range for slice of length 0`.

      Reachable pre-authentication on UDP (`rdnsd/src/main.rs:1114`), TCP
      (`:674`), in `rdnsr` with no validator in front of it at all
      (`rdnsr/src/main.rs:596`), and in `xfr.rs:709` — where a hostile primary
      kills a secondary's replication task, which is **not restarted**, so that
      zone silently stops refreshing until EXPIRE. Contained today only because
      the parse sits inside a `tokio::spawn`; that is incidental, and
      `panic = "abort"` would make it a process kill.

      ```rust
      let rdatalen = rdatalen as usize;
      if rest.len() < rdatalen {
          return Err(anyhow!("RDATA declares {rdatalen} bytes, {} remain", rest.len()));
      }
      let (rdata, rest) = rest.split_at(rdatalen);
      ```

      A probe test for exactly this was written and thrown away twice during the
      review. Land it as a regression test this time.
- [x] **`DnsCache` sign-extends a negative TTL, pinning an entry forever** —
      **done 2026-07-28.** `.max(0)` *before* the widening, a `MAX_CACHE_TTL`
      ceiling of a day (RFC 8767 §4), and `saturating_add` for the expiry. Tested
      through the public API — put a record with a negative TTL, assert the get
      misses — rather than by reading the private field, because "never expires"
      is the bug and the field is only how it happened. The `Ttl(u32)` newtype the
      finding recommends is the better fix and is **not** done: it would make the
      sign unrepresentable and retire ~30 individually load-bearing `as u64` /
      `.max(0)` sites, which is worth doing and is a separate change. Original
      finding follows.

      (`rdns/src/cache.rs:106`). `ResourceRecord::ttl` is `i32` straight off the
      wire (`lib.rs:827`); a TTL with the high bit set parses negative, `-1 as u64`
      is `u64::MAX`, `min` picks it, and `is_expired` is false for the life of the
      process — a poisoned answer immune to the re-query that would otherwise
      correct it. `now + min_ttl` can also overflow-panic in debug. RFC 2181 §8
      says treat a negative received TTL as 0. `negative_cache.rs:149` and
      `nsec_cache.rs:214` already clamp; the positive cache is the one that does
      not, and `resolver.rs:1195`/`:1229` write `rr.ttl.max(0)` while the cache
      behind them does not. Fix now with `r.ttl.max(0) as u64`, a ceiling
      (`MAX_CACHE_TTL`, a day) and `saturating_add`. Fix properly by making the
      sign unrepresentable: a `Ttl(u32)` newtype clamping once at the parse
      boundary, so the ~30 downstream `as u64`/`.max(0)` sites stop being
      individually load-bearing.
- [x] **One oversized UDP datagram terminates `rdnsd` on Windows** — **done
      2026-07-28.** Both halves: the predicate now matches raw 10040 and
      `ErrorKind::InvalidInput`, and the receive buffer is 65535 — a request is
      not bound by the payload size we advertise for *responses*, which is where
      the 4096 came from. The predicate moved into `utils::recv_error_is_transient`
      and `rdnsr` uses it too, because it existed twice and this case had been
      found in neither copy; that duplication is now a rule in `CLAUDE.md` §7. The
      test drives it through `Error::from_raw_os_error`, since the kind carries no
      information — which is exactly why a `matches!` on kinds missed it. Original
      finding follows.

      (`rdnsd/src/main.rs:1065`, `is_stray_icmp` at `:1053`). The receive buffer is
      `vec![0; 4096]`; on Windows a larger datagram makes `recvfrom` fail with
      **WSAEMSGSIZE** rather than truncate. Confirmed: Rust maps it to
      `kind=Uncategorized raw=Some(10040)`, which `is_stray_icmp` does not match
      (it covers only `ConnectionReset | ConnectionRefused | NetworkUnreachable |
      HostUnreachable`), so it falls to the fatal arm at `:1071` → `udp_loop`
      returns → `serve`'s `select!` propagates → the process exits. **This is the
      development machine's platform**, so it is a dev-loop hazard as much as a
      production one, and it is the same class as the ICMP bug the comment block
      at `:1040-1052` was written to fix. Two parts: add the size case to the
      non-fatal set (raw 10040, and `ErrorKind::InvalidInput`), and size the buffer
      honestly — 4096 matches `RDNSD_PAYLOAD_SIZE` for *responses*, but a request
      is not bound by it. On Linux the same packet is silently truncated and then
      fails to parse, so the client gets nothing rather than FORMERR; the buffer
      fix addresses both.
- [x] **Two per-IP maps are unbounded; a spoofed-source flood is a memory DoS** —
      **done 2026-07-28**, all three maps. `logging::note_source` bounds both
      counters at 10,000 sources: an existing source always counts, a new one is
      admitted while there is room, and at the bound every count is **halved** and
      the entries reaching zero are forgotten. That keeps the heavy hitters the
      counters exist to find and drops the single-datagram sources a spoofed flood
      is made of, at amortized O(1) — a scan for the smallest count on every
      insertion would have been O(n) per packet, which is worse than the problem.
      A new `untracked_sources` field says when the per-IP figures became a sample
      rather than a census, because a "top talkers" list that is quietly a lie is
      worse than none. `RateLimiter` gets a `max_tracked` and *allows* a source it
      has no room for: failing closed there would let one flood deny service to
      everybody. The bound is a parameter of `note_source` so a test can check the
      boundary at a size a reader can follow. Original finding follows.

      (`rdns/src/logging.rs:16` and `:20`, `rdns/src/security.rs:40`). Four of the
      five reviewers hit this. `QueryStats::queries_by_ip` and `rate_limited_ips`
      are **never** trimmed — `reset_stats()` exists and is called from nothing but
      tests. `RateLimiter::buckets` is trimmed only every
      `cleanup_interval_secs = 600`, and an entry is created *before* any
      validation, so it costs an attacker one spoofed 12-byte datagram per entry.
      With IPv6 source addresses this is unbounded in practice, and the 600 s
      cleanup then walks the whole map under the lock.

      `ResponseLimiter` two hundred lines away already solves this
      (`max_tracked: 10_000` plus `forget_idle`, `security.rs:160-164`) with a
      comment explaining that the table would otherwise be the next amplification
      vector. That reasoning applies verbatim to the two limiters that run
      *first*; they just never got it. For the logger, per-IP counters are the
      wrong shape for an unbounded key space at all — a top-K or a sketch gives
      the same anomaly signal in constant memory.
- [x] **`RateLimiter` subtracts wall-clock timestamps without saturation** —
      **done 2026-07-28.** `saturating_sub` at all three sites, and
      `.lock().unwrap()` replaced with `let Ok(..) = .. else` on both paths a query
      reaches, each with a commented failure decision: `should_allow` allows,
      because a limiter whose state is unknown must not become a total outage.
      **The same defect was in `logging::log_query`** — two more unsaturated
      timestamp subtractions under the stats mutex — and is fixed with it; that one
      was not in the original finding, which is why "every subtraction of two
      timestamps is `saturating_sub`, no exceptions" is now a rule
      (`CLAUDE.md` §6). Moving both limiters to `Instant` is still the right
      answer and is not done. Original finding follows.

      (`rdns/src/security.rs:71`, and `:101`), inside the lock. `current_unix_timestamp()`
      is `SystemTime`, not monotonic. An NTP step backwards panics with the guard
      held (poisoning the mutex, after which every `should_allow` panics at
      `:64` and the server stops answering entirely) or, in release with overflow
      checks off, wraps to ~1.8e19 so `tokens_to_add` refills every bucket to full
      and the limiter silently resets. `ResponseLimiter::admit` at `:244` uses
      `saturating_sub` correctly. Use `saturating_sub` in both places, replace
      `.lock().unwrap()` with a fail-closed `let Ok(..) = .. else`, and ideally
      move both limiters to `Instant`.

#### 9c. Silent wrong answers in operation

The theme: serving a wrong DNS answer is worse than serving none, and every item
here degrades quietly with the process healthy and nothing alerting.

- [x] **A zone file that fails to parse is dropped and the server stays up** —
      **done 2026-07-28.** `enumerate_zone_files` collects every failure, reports
      them all, and refuses the set; `--allow-partial-load` is the flag for the
      operator who genuinely wants the old behaviour, because 39 of 40 zones does
      beat none when that is really the choice. All failures are listed rather
      than the first, so a deploy is fixed in one pass instead of one typo per
      restart.

      **The change is really that three questions stopped being one.** "Could the
      directory be read?" is always fatal; "did every file parse?" is fatal unless
      the flag says otherwise; "is it empty?" is fatal except for a secondary that
      has not had its first transfer yet. `load_zones_from_source` now answers the
      third, because it is the only one of the three that knows whether its caller
      is a secondary — see the correction under the next bullet. Original finding
      follows.

      (`rdnsd/src/main.rs:2408`, the `Err(e) => { eprintln!(...); }` arm).
      Verified live: three zone files, one with a bad record, exit code 0, process
      serving, the broken zone answering **REFUSED** — indistinguishable from a
      zone that was never configured. `enumerate_zone_files` aborts only if
      *every* file fails.

      This defeats the invariant `Reloading::load`'s own doc comment
      (`rdnsd/src/main.rs:1270`) claims to uphold: *"Nothing is installed unless
      the whole set comes through… A reload that replaced half the zones and gave
      up would leave the server serving a mixture."* It does not hold — a SIGHUP
      taken while config management is mid-write drops every not-yet-written zone
      from a set that `install_all_zones` then installs wholesale (`:1569`), so
      **a broken zone file on reload takes down a previously-working zone.** One
      typo in 1 of 40 zones plus a deploy SIGHUP is a lame delegation for that
      zone, 39 green dashboards, and one stderr line that scrolled past hours ago.
      Fix: collect errors and fail the whole load; add `--allow-partial-load` for
      the operator who genuinely wants today's behaviour.
- [x] **An unreadable zone directory silently unloads every zone** — **done
      2026-07-27**, and the fix was half wrong until 2026-07-28. Deleting the
      `.unwrap_or_default()` was right. The claim that came with it —
      *"`enumerate_zone_files` already returns `Ok(empty)` for an empty directory,
      so the `replicating` intent is unaffected"* — **was false**, and it was
      written into the commit message, the doc comment and this file without
      anyone checking it: that function returned `Err("No .zone files found in
      directory")` for an empty one. So the swallowed error *was* the only thing
      making a secondary's first start work, and removing it meant a secondary
      pointed at an empty `--zone-dir` refused to start at all.

      Nothing caught it, because nothing tested a secondary starting from an empty
      directory — a green suite again standing in for evidence it never had. The
      emptiness check now lives in `load_zones_from_source`, which is the only
      place that knows whether the caller is replicating, and
      `a_secondary_may_start_with_an_empty_zone_directory` pins it. Left written
      down rather than edited out, because "I asserted what the callee does
      instead of reading it" is the interesting part and is now `CLAUDE.md` §4.
      Original finding follows.

      (`rdnsd/src/main.rs:2348`): `return Ok(enumerate_zone_files(dir).unwrap_or_default());`
      on the `--secondary` path. An `Err` — permission change, NFS blip, all files
      failing to parse — becomes `Ok(empty map)`, `Reloading::load` sees success,
      and `install_all_zones` installs it. The server is up, listening, and holding
      zero zones; every query REFUSED. **Delete the `.unwrap_or_default()` and
      propagate.** One line, and the best effort-to-risk trade on this list.
- [x] **SIGHUP resurrects a secondary zone that was withdrawn for EXPIRE** —
      **done 2026-07-28.** `expire_stale_zones_at_startup` is now
      `withdraw_unvouched_zones` and runs after *every* fill of the zone map,
      startup and reload alike — `Reloading` carries the specs and the zone
      directory for that purpose. Expiry that lasts only until the next deploy is
      not expiry.

      Both halves are closed. A missing state entry for a zone that is loaded now
      means "unknown age → do not serve" rather than `continue`: `StateFile::load`
      returning empty is right for a cache and wrong here, because forgetting the
      last-contact time *is* the difference between withdrawn and served. The zone
      returns at the first successful transfer, which is what makes it ours to
      answer for. An entry naming a different master is treated the same way,
      since it is not evidence about this one. Four tests, including the control
      that a zone in contact keeps being served — the check has to be narrow.
      Original finding follows.

      (`rdnsd/src/main.rs:2023`). `expire_stale_zones_at_startup` is called from
      `main` only, never from the reload path, and `Reloading::load` re-reads every
      `.zone` file from disk without consulting the state sidecar. A zone correctly
      withdrawn because its primary has been unreachable for a week comes straight
      back and is served **with AA set** — precisely the "permanently wrong answers
      nobody can see are wrong" that the withdrawal code's own comment says it
      exists to prevent. Same hole from the other side: if the sidecar is missing
      or unreadable, `StateFile::load` returns empty by design
      (`secondary.rs:232`, "Never fails"), `expire_stale_zones_at_startup` hits
      `continue`, and the stale copy is served authoritatively from a cold start.
      "Missing state degrades, never crashes" (see "Architecture: persistence") is
      right for a cache and **wrong for expiry** — forgetting the last-contact time
      *is* the difference between withdrawn and served. Fix: factor the check out
      and call it after every `install_all_zones`; treat a missing state entry for
      a zone whose file exists on disk as "unknown age → do not serve".
- [x] **A negative answer reached through a CNAME gets AD=1 without its denial
      being checked** — **done 2026-07-28**, along the lines the finding
      prescribes. `validate` asks `cname_chain_shape` where the answer actually
      ends and whether an RRset of the queried type is there; a chain that ends
      without one is negative, and `check_denial` runs against the **end of the
      chain** rather than the name asked about (RFC 4035 §5.4).

      One thing the finding did not mention and the fix needs: on that path the
      *answer* section has to be verified too. A CNAME-terminated "no" hands the
      client a chain of real records alongside the denial, and validating only the
      authority section would authenticate half the answer. So `records` is the
      answer section, plus the authority section when the response is negative —
      which for a chainless negative answer is exactly what it was before.

      Confirmed by reverting: with `answers.is_empty()` restored, a NODATA whose
      proof has simply been **deleted** after a legitimate CNAME comes back
      `secure`. No forged signature required. Two tests, the control and the
      attack. Original finding follows.

      (`rdns/src/resolver.rs:1410`, `:1487`, `:1614`).
      `let negative = response.answers.is_empty()` — but `recurse` returns the
      accumulated CNAME chain in `answers`, so for
      `www.example.com CNAME cdn.example.net` where the target has no AAAA,
      `negative` is false and `check_denial` never runs. `cname_chain_shape`
      returns `Intact { final_name }` and `validate()` pattern-matches only
      `Broken`, discarding it, so validation falls through to `Secure` at `:1496`.
      The last hop's authority section is neither signature-verified nor tested for
      whether it denies anything, and `rdnsr` then sets AD (`rdnsr/src/main.rs:807`)
      and caches it as validated (`:765`). Strip or forge the terminal
      NODATA/NXDOMAIN after any legitimate CNAME and it is handed to clients as
      authenticated — a downgrade relative to the non-CNAME path, which is handled
      correctly. RFC 4035 §5: a validator MUST authenticate negative responses, and
      §5.4 keys the proof to the name actually denied. Fix: use
      `Intact { final_name }` — when the answer holds no RRset of `qtype` at
      `final_name`, treat the response as negative and run `check_denial` against
      `final_name`, after verifying the authority section with `validate_records`.
- [x] **`rdnsr` answers messages with QR=1, and answers any opcode as a query** —
      **done 2026-07-28.** `handle_query` drops a message with QR set before
      anything else, and answers NOTIMP to every opcode but QUERY with the
      client's own opcode echoed (RFC 1035 §4.1.1) and its OPT mirrored
      (RFC 6891 §6.1.1). `build_response` takes the opcode as a parameter rather
      than hardcoding QUERY — every caller passes QUERY and is right to, but
      hardcoding it is what made the missing check invisible.

      **`rdnsd` had the QR half too**, as the finding says, and it is fixed with
      it: `RequestValidator` deliberately accepts QR=1 because it is used on both
      directions of the wire, so the check belongs at the point where we know the
      packet arrived at a listening socket. `rdnsr` had no test module at all
      before this; it has one now. Original finding follows.

      (`rdnsr/src/main.rs:596`, `:882`). `handle_query` parses and goes straight to
      `msg.queries.first()`, never testing `msg.response` or `msg.opcode`, and
      `build_response` hardcodes `opcode: OpCode::Query`. Two consequences: a
      *response* sent to `rdnsr` is resolved and replied to, so two instances
      pointed at each other — or one spoofed packet with a forged source — is a
      self-sustaining packet loop; and a NOTIFY or UPDATE gets a plausible
      QUERY-shaped answer instead of NOTIMP. `rdnsd` checks the opcode
      (`main.rs:242`) but also skips the QR test. RFC 1035 §4.1.1: opcode is
      "copied into the response". This is the "no opcode check" already noted at
      the end of #6 — the QR half is new, and is the one that loops.

#### 9d. Operability — none of this is visible from outside the process

- [ ] **The query rate limiter is hardcoded at ~10 q/s per source IP, drops
      silently, and has no flag** (`rdns/src/security.rs:22-27`, wired
      unconditionally at `rdnsd/src/main.rs:501`). Measured live: a 60-query burst
      from one address got **20 answers and 40 silent drops** — no REFUSED, no
      SERVFAIL, nothing on the wire. Put this behind any ISP resolver or public
      resolver and you blackhole the bulk of its traffic while `dig` from a laptop
      works perfectly, so the operator concludes it is the network. `log_rate_limited`
      increments a map nothing ever reads. Fix: `--query-rate`, `--query-burst`,
      `--query-rate-exempt <CIDR>`, and a default at least 10× higher — or off for
      `rdnsd`, which fronts resolvers rather than end users.
- [ ] **Nothing re-signs a running server** — already #8's first bullet, and the
      review confirms the 3am shape: exactly `--signature-validity` days after the
      last deploy, every validating resolver SERVFAILs the entire zone at once,
      while the server is healthy and `dig +norec` looks perfect. Until the timer
      exists, a cron `kill -HUP` is **mandatory documented deployment config**, and
      an alert on `now - zone_signed_at > validity/2` is what makes it survivable.
- [ ] **There are no metrics: `init_telemetry` is never called, and the module
      with the useful counters is wired to nothing.** Verified by grep — the only
      match for `init_telemetry` in the workspace is its own definition at
      `rdns/src/telemetry.rs:13`, and it is a stub that builds two exporters into
      `let _trace_exporter`/`let _metrics_exporter` and drops them. No tracer
      provider, no meter provider, no OTLP endpoint flag. **The README's
      "OpenTelemetry integration for tracing and metrics" is not true.**

      Because nothing initialises `tracing_subscriber`, every `tracing::` call in
      `telemetry.rs::instrumentation` — the whole instrumentation layer, on every
      query path — compiles in and discards. And `rdns/src/metrics.rs`, which
      *does* have the RED metrics worth paging on (`responses_servfail`,
      `responses_nxdomain`, `responses_refused`, per-qtype, `rate_limited`) plus a
      working `to_prometheus_format()`, is referenced **only by `bench.rs`**. Both
      servers use the other `DnsMetrics` in `telemetry.rs`, whose
      `dnssec_validations`/`dnssec_failures` `rdnsd` never increments.

      Fix: delete `telemetry.rs::DnsMetrics`, wire `metrics.rs::DnsMetrics` into
      both servers, add `--metrics-listen <ADDR>` serving `to_prometheus_format()`
      (most DNS shops scrape; OTLP push is the wrong default here). Then add a
      latency histogram, a per-zone serial-currently-served gauge, and a
      seconds-since-last-successful-transfer gauge — the three an operator
      actually asks for. **Decide the OTel question in the same breath**: the
      `opentelemetry 0.24` family is many releases behind, the lock carries two
      copies (0.23 *and* 0.24, via `tracing-opentelemetry 0.24`), and it drags
      `tonic`/`prost`/`hyper`/`h2` — ~40 crates and a gRPC server — into a DNS
      daemon for an exporter that never initialises. Either finish the export
      (a coordinated bump of all four OTel crates plus `tracing-opentelemetry`,
      no incremental path) or delete five dependencies.
- [ ] **No SIGTERM handling anywhere** (grep for `SIGTERM`/`SIGINT`/`ctrl_c`
      across all four crates returns nothing; only SIGHUP exists).
      `systemctl stop`, `docker stop` and a Kubernetes eviction all kill the
      process instantly: in-flight TCP zone transfers are cut mid-stream, and the
      client cannot distinguish a truncated AXFR from a complete one — the code
      says so at `rdnsd/src/main.rs:856`. A `write_zone_file` in progress leaves a
      `.zone.tmpNNN` sibling; `persist` cleans up on *error*, not on signal.
      Compounding it, `serve`'s `tokio::select!` over the two `JoinHandle`s
      *drops* the loser, which detaches rather than cancels, so `main` returns with
      replies still queued in the per-connection `mpsc`. Fix: a
      `CancellationToken` both loops select on, `tokio::signal::ctrl_c()` plus
      SIGTERM, stop accepting, bounded drain (~5 s), exit 0. `announce_zones`'
      fire-and-forget NOTIFY tasks want a `JoinSet` so shutdown can drain them.
- [ ] **A malformed-packet flood becomes a disk fill and a global lock convoy**
      (`rdns/src/logging.rs:96`). `log_error` does an unconditional, unbuffered
      `eprintln!` while holding the stats mutex — one `write(2)` per bad packet,
      serialized on both Rust's stderr lock and the mutex, from `answer`
      (`main.rs:662`, `:675`), the UDP task (`:1102`, `:1241`) and every TSIG
      rejection. There is no `--log-level` or `--quiet` on either binary, so it
      cannot be turned off. The caller compounds it:
      `log_error(peer.ip(), &format!("invalid query: {}", ...))` allocates the
      message whether or not anything wants it. At 50k pps of garbage that is 50k
      journald lines a second, `/var/log` fills, journald drops logs for *every
      other service on the box*, and the logging is itself the amplifier.
      Fix: route through `tracing` with real levels (so the `format!` is not
      evaluated when disabled), count under the lock and log outside it, sample or
      rate-limit the error path.

      **Note the level inversion on the other side**: `trace_query_response`
      (`telemetry.rs:263`) logs the **query name at INFO on every successful
      query**. It is inert only because `tracing_subscriber` is never initialised —
      fixing the metrics item above switches on full per-query logging by default,
      with the client IP, with no runtime toggle. Query logging must be explicit
      opt-in, with the client IP behind a second switch, before that lands.
- [ ] **Unbounded `tokio::spawn` per UDP datagram on both daemons**
      (`rdnsd/src/main.rs:1077`, `rdnsr/src/main.rs:477`) — TCP has both
      `MAX_TCP_CONNECTIONS` and `MAX_INFLIGHT_PER_CONNECTION`, UDP has neither.
      Already noted for `rdnsr` at the end of #6; it is equally true of `rdnsd`.
      Worse, `rdnsd` runs `should_allow` as the first thing *inside* the spawned
      future (`:1092`), so the `to_vec()`, two `Arc` clones and the task are all
      paid before anything decides to drop the packet. Fix: check the limiter and
      the validator inline on `&buf[..size]` in the recv loop, then
      `try_acquire_owned` on a `Semaphore` sized by `--max-concurrent-udp` —
      `try_`, not `acquire`, because for UDP shedding is correct back-pressure and
      awaiting would just move the queue into the kernel buffer.
- [ ] **Blocking I/O and full zone parse-and-sign run on the tokio runtime**
      (`rdnsd/src/main.rs:1846`, `:1814`, `:2342`). `record_state` → `StateFile::record`
      → `persist::write_atomically_str` does `File::create` + `write_all` +
      **`sync_all`** + `rename` + a directory fsync, synchronously, on a worker
      that is also serving queries — and holds a `std::sync::Mutex` across the
      fsync, so a second secondary loop spins a worker rather than yielding.
      `load_zones_from_source` is an `async fn` **containing zero await points**:
      `read_dir`, `read_to_string` per zone, full parsing, then `signing.apply`
      (ring ECDSA over every RRset), invoked from the SIGHUP task at `:1302` while
      both listeners are live. The declared-`async`-but-fully-blocking signature is
      the trap — it reads as if it yields. Fix: `spawn_blocking` for each, and make
      the state mutex a `tokio::sync::Mutex` (or move the write outside the guard).
- [ ] **A full zone diff runs while the zone-map write lock is held**
      (`rdnsd/src/main.rs:1521`, `:1550`). `install_zone` takes `zone_map.write()`,
      then `deltas.write()`, then calls `note_change` → `ixfr::diff`
      (`ixfr.rs:175`), which walks every record of both versions into a
      `BTreeMap`. On SIGHUP `install_all_zones` does that for *every* zone inside
      one write guard, so every query blocks for the sum of the diffs — the exact
      stall the comments at `main.rs:729` and `:1170` took trouble to avoid on the
      read side. Fix: compute under the read lock, apply under the write lock.
      Cheap once zones are `Arc<Zone>` (see 9e).
- [ ] **No config file; TSIG secrets go on the command line**
      (`rdnsd/src/main.rs:70-181`). `--tsig-key <[ALG:]NAME:SECRET>` puts the
      base64 HMAC secret in `argv`, world-readable in `ps aux` and
      `/proc/<pid>/cmdline`, in shell history, and copied verbatim into the
      systemd unit the README tells you to write. At 40 zones and 6 keys that is a
      multi-kilobyte, undiffable exec line maintained by hand: one `--secondary`
      per zone, one `--tsig-key` per key, plus `--also-notify` per target. There is
      no per-zone configuration at all (every zone gets the same signing policy,
      NSEC/NSEC3 choice and validity) and no dry run. Fix: `--config <FILE>` (TOML)
      with a `[zones.<name>]` table, `--tsig-key-file` reading mode-0600 secrets,
      and `--check-config` that validates and exits without binding. Largest item
      here, and the one that makes the rest configuration-manageable.
- [ ] **Any configured TSIG key authorizes a transfer of every zone**
      (`rdnsd/src/main.rs:796`). `answer_transfer` asks only whether a session
      exists — `authenticated_by.is_none()` — so holding *any* key in the keyring
      transfers *any* zone, and bypasses `--allow-transfer` entirely. `TsigKeyring`
      (`tsig.rs:168`) is a flat list with no key→zone binding, and the
      `[alg:]name:secret` spec format has no field to express one. Hand a
      per-customer key to one partner and you have handed them every zone on the
      server, including zones whose ACL names nobody. Fix: an allowed-zone list per
      key, checked against the requested apex before the messages are built.
- [ ] **No control channel — the runbook answer is "read the logs", and the logs
      are unstructured `println!` with no timestamps.** Of the four questions an
      operator asks at 3am, exactly one is answerable: *"is example.com loaded, at
      what serial?"* (query the SOA). *"Is broken.test loaded?"* — REFUSED, which
      is identical to a zone that was never configured. *"Is the secondary in
      sync?"* — read the state sidecar off the box by hand. *"Why did this query
      SERVFAIL?"* — `rdnsd` barely emits SERVFAIL at all. Fix:
      `--control-socket <PATH>` with `status` (zones, serials, load time, per-zone
      last transfer), `reload [zone]`, and `dump <zone>` — `zone_writer` already
      exists for the last one and has no CLI surface yet (noted at #7 step 2).
- [ ] **Docs an operator will copy from are wrong.** `docs/CLI_USAGE.md:366` and
      `:382-391` still document the `rdnsd udp` / `rdnsd tcp` subcommands, and
      README.md:31-34 has them too — both **removed**, as line 25 of CLI_USAGE.md
      itself explains; copy either and the daemon refuses to start.
      `CLI_USAGE.md:100` claims `--zone-dir` "recursively searches" for `*.zone`
      files — `enumerate_zone_files` is a flat `read_dir`, so organising 40 zones
      into subdirectories serves nothing. The README's systemd unit (`:106`) omits
      `User=`/`Group=` (it runs as root, reading private signing keys as uid 0) and
      omits every flag a real deployment needs. Also: no privilege drop exists
      anywhere — no `--user`/`--group` to drop after binding 53 — and the README's
      `sudo rdnsd` suggestion should go.
- [ ] **No CI, and `deny.toml` has never been green.** No `.github`, no CI config
      of any kind: nothing runs the 553+37 tests or clippy on push. No MSRV is
      pinned anywhere (no `rust-version`, no `rust-toolchain.toml`) while the
      README asserts "Rust 1.95.0+". All three crates are `version = "0.1.0"`, so
      `--version` cannot identify a build. `deny.toml` is the **unmodified upstream
      template** — `allow = ["MIT", "Unicode-DFS-2016"]` with Apache-2.0 left
      commented out, so it would fail on `ring` (Apache-2.0 AND ISC) and
      `unicode-ident` (Unicode-3.0) the first time it ran; and it *cannot* run here
      anyway, because cargo-deny 0.16.1 errors with "unknown variant `2024`" on an
      edition-2024 crate in the graph. Both workspace crates declare
      `license = "MIT OR Apache-2.0"` while the repo ships only an MIT `LICENSE`.
      Fix: GitHub Actions running build + test + clippy + a cargo-deny new enough
      to parse edition 2024; pin the MSRV; stamp the version from git; add the
      Apache license file or drop the claim.
- [ ] **Private key permissions are best-effort on write and unchecked on read**
      (`rdns/src/dnssec_key.rs:590`, `:472`). `--generate-keys` does
      `let _ = set_permissions(..., 0o600)` on Unix and nothing at all on Windows;
      `load_dir` reads whatever is there with no check and no warning. A key
      directory restored from backup as 0644, or `chmod -R`'d by a deploy script,
      is silently accepted with a world-readable zone-signing key.
- [ ] **No container image, no readiness signal** — no Dockerfile, no
      `Type=notify`/sd_notify, no health endpoint. With `Restart=on-failure` and no
      readiness gate, a rolling restart moves traffic to an instance that has bound
      the socket but is still parsing 40 zones. Cheap once the metrics listener
      above exists (`/healthz` on it).

#### 9e. Performance — all measured under `--release`

Every item below except the first was found by reading code and confirmed by
timing it. **Do the first one first**: it turns the rest from a list of claims
into a measurement you can re-run, and it is what tells you when to stop.

- [ ] **Profile the allocation pattern with DHAT, then drive it down.** The
      findings below are individually true but were each found by hand, which
      means the list is certainly incomplete and none of it is guarded against
      coming back. `dhat` (the crate — Nicholas Nethercote's Rust port) answers
      "how many allocations, how big, from which line" for a real workload, and
      the answers are the input to every other item in this section.

      **It runs natively on Windows — verified on this machine, 2026-07-27.** No
      Valgrind, no Linux VM. The Valgrind tool and the crate share only an
      output format and a viewer; the crate is a global-allocator shim that
      records a backtrace per allocation and writes `dhat-heap.json` on `Drop`.
      Symbolization works: the frame table resolves to `file.rs:line`. A probe
      reproducing `to_bytes_within`'s shape (below) reported **65,560,600 bytes
      live in 1,002 blocks** for 1000 sixty-byte responses, which is the
      independent confirmation of the 64 KiB item three bullets down.

      Wiring, feature-gated so a normal build never sees it:

      ```toml
      # rdnsd/Cargo.toml
      [dependencies]
      dhat = { version = "0.3", optional = true }
      [features]
      dhat-heap = ["dep:dhat"]

      # workspace Cargo.toml — without this the frame table has no file:line
      [profile.release]
      debug = 1
      ```
      ```rust
      #[cfg(feature = "dhat-heap")]
      #[global_allocator]
      static ALLOC: dhat::Alloc = dhat::Alloc;
      // first line of main(), held for the life of the process:
      #[cfg(feature = "dhat-heap")]
      let _profiler = dhat::Profiler::new_heap();
      ```

      Three things that will otherwise waste an afternoon:

      - **The profiler writes on `Drop`, so a daemon that never returns from
        `main` never writes the file** — and there is no SIGTERM handler yet
        (#9d), so Ctrl-C kills it before the drop runs. Either give the profiling
        build a bounded-query exit, or do the graceful-shutdown item first. They
        compose in that order.
      - **Never read timing numbers from a DHAT build.** Collecting a backtrace
        per allocation dominates everything; it answers how many and how big, not
        how fast. The nanosecond figures in the items below were measured
        *without* it and re-measuring them under it will contradict them for the
        wrong reason.
      - **The viewer is the loose end.** `dh_view.html` ships with Valgrind, which
        is not installed here; there is a hosted copy on the author's GitHub
        Pages but that URL was **not** verified from this machine. The JSON is
        self-contained and readable directly for simple questions — the 65 MB
        figure above was read straight out of it.

      What to actually measure, in order: one UDP query end to end (the target is
      the per-query allocation *count*, and the interesting number is how much of
      it is response serialization); one full zone load and sign; one AXFR out;
      one recursive resolution with validation. Each has a different shape and the
      last two are where a surprise is most likely, since nobody has looked.

      **Then pin the results as tests, which is the part worth the effort.**
      `dhat::Profiler::builder().testing()` plus `dhat::assert_eq!` on
      `HeapStats::get().total_blocks` turns "N allocations per query" into an
      exact assertion:

      ```rust
      let _p = dhat::Profiler::builder().testing().build();
      // ... serialize one response ...
      dhat::assert_eq!(dhat::HeapStats::get().total_blocks, 1);
      ```

      Several findings below *are* allocation-count claims — ~8 per compressed
      name, 2–4 per query for re-parsed EDNS, one 64 KiB block per response — and
      an exact count does not have `bench.rs`'s failure mode. A wall-clock floor
      gets moved when the machine is busy, which is how the `log_query` quadratic
      survived (see the next item and "Current state"); an allocation count is
      deterministic and does not care what else is running. Put these under
      `benches/` or a `#[test]` alongside the criterion conversion at the end of
      this section, not in `bench.rs`.

      A scratch project that already does the wiring is at
      `scratchpad/dhat_probe` (session-local — recreate from the snippet above if
      it is gone).

- [ ] **`QueryLogger::log_query` is O(window) per query under one global mutex —
      a hard ~23k qps ceiling** (`rdns/src/logging.rs:80`, lock at `:58`).
      `window.queries.retain(|&t| t > age_limit)` rescans every timestamp from the
      last 10 s on **every** query, so the vector is `10 × qps` long and the cost
      is linear in it. Measured: 469 ns at 1k depth, 2,364 at 10k, 9,886 at 50k,
      19,419 at 100k — dead linear at ~0.19 ns/element. Setting that against the
      per-query budget gives a steady-state ceiling of **≈22,700 qps for the whole
      server**, and because `stats` is held across the entire function including
      both `query_window` acquisitions, it does not improve with core count.

      **This is what `bench_logger_throughput`'s floor was lowered for.** The
      "Current state" note above attributes the flakiness to competing load; it is
      this quadratic, and moving the threshold from 45k to 10k ratified the
      regression the benchmark had caught. Fix: the window exists only to compute
      QPS every 5 s — replace it with `count` + `window_start` + `last_qps` as
      relaxed atomics (one `fetch_add` per query), or a `VecDeque` with
      `pop_front` while the head is stale (amortized O(1)). Split the `stats`
      mutex from the window and drop the double acquisition at `:70-75`, which
      takes a lock twice to read the constant `10`.
- [ ] **Every response allocates and hands a 64 KB buffer to `send_to`**
      (`rdns/src/lib.rs:1058`, `:1075`). `to_bytes_within` does
      `vec![0u8; u16::MAX as usize]` — 64 KB, zeroed, per response — and
      `Vec::truncate` **does not release capacity**, so the Vec passed to
      `send_to` and held until the send completes is 64 KB regardless of the
      answer. Confirmed: a 60-byte response retains capacity 65535. At 1,000 in
      flight that is 64 MB resident for a few hundred KB of payload, a 1000×
      overshoot. Throughput cost measured on a 3-record response: 1043 ns/resp vs
      718 ns with a reused buffer — 31% of serialization is pure allocator
      traffic, and it is not optimizer-erasable because the allocation escapes into
      `send_to`. Fix: size the scratch to `max_len` (UDP callers pass 4096; only
      the AXFR/TCP paths pass `u16::MAX`), and add
      `to_bytes_within_buf(&self, max_len, &mut Vec<u8>)` so the datagram path
      reuses a per-task scratch buffer and allocates nothing.
- [ ] **`DnsCache` eviction is O(n²) with a `String` clone per removal, under the
      global cache lock** (`rdns/src/cache.rs:135`). The loop re-scans the entire
      map with `min_by_key` to find *one* victim, and runs until half the entries
      are gone: at the default `max_entries = 10_000` that is ~37 million HashMap
      iterations plus 5,000 `String` allocations in one uninterruptible stall with
      every reader blocked — and it repeats as soon as the cache refills. Fix: one
      pass with `select_nth_unstable_by_key` to partition, or a Redis-style random
      sample (5 candidates, drop the soonest) for amortized O(1). The same
      `retain`-then-`min_by_key` shape is at `nsec_cache.rs:841`/`:862` and
      `negative_cache.rs:253` — bounded much smaller there, so lower priority, but
      it should not spread further.
- [x] **`DnsCache` keys on Unicode `to_lowercase()`, collapsing distinct names
      into one slot** — **done 2026-07-28.** Both sites use the new
      `utils::ascii_lowered`, whose doc comment carries the reason so the next copy
      is not written wrong: it was correct in `zone.rs` *with* the explanation and
      wrong in `cache.rs` without it. Tested with U+212A KELVIN SIGN, which
      `to_lowercase` folds to `k`. The negative cache and the compressor were left
      alone here — they are the other half of this bullet's "cannot drift apart
      again" and are listed under name compression below. Original finding follows.

      (`rdns/src/cache.rs:65`, `:119`). DNS case-insensitivity is
      ASCII-only (RFC 4343), but `str::to_lowercase` applies the full Unicode
      mapping, which folds codepoints *into* ASCII. Confirmed: U+212A KELVIN SIGN
      (wire bytes `E2 84 AA`) lowercases to `k`, so `\u{212A}.example.com.` and
      `k.example.com.` share one cache entry — two different owners, different
      bytes on the wire. `zone.rs:279` uses `make_ascii_lowercase` *with a comment
      explaining exactly why*; the cache drifted from it. Fix both sites, and hoist
      a shared `ascii_lowered` helper so cache, zone, negative cache and compressor
      cannot drift apart again. It is also the faster choice — a vectorizable byte
      loop instead of char-by-char Unicode table lookups.
- [ ] **Name compression allocates two `String`s per suffix per name**
      (`rdns/src/compression.rs:63`). `labels[i..].join(".").to_ascii_lowercase()`
      allocates once to join and **again** to lowercase (`to_ascii_lowercase` does
      not mutate in place). Writing `www.example.com.` cold costs ~8 allocations,
      total bytes quadratic in label count. Measured at 339 ns/name, which makes
      compression the majority of response serialization — the whole rest of
      `to_bytes` for a 3-record answer is under 400 ns. Cheapest fix: build the
      joined key and `make_ascii_lowercase()` in place, halving it immediately.
      Real fix: lowercase the name once into a scratch buffer and key on
      `(hash, offset, len)` in a `Vec` with linear scan — a message holds a handful
      of distinct names, so that beats `HashMap<String, u16>` outright and removes
      the per-message HashMap construction too.
- [ ] **EDNS is re-parsed two to four times per query**
      (`rdnsd/src/main.rs:220`, `:236`, `:399`, `:1151`, `:1182`;
      `rdnsr/src/main.rs:611`, `:622`, `:624`). `msg.edns()` runs
      `Edns::from_record` → `parse_options`, allocating a `Vec<EdnsOption>` plus a
      `Vec<u8>` per option, then throwing it away — and `make_response` calls it
      twice in sixteen lines. Parse once into a local (or a small `Copy` struct of
      payload size, version and DO, since the option list is never read on this
      path) and thread it through.
- [ ] **DNSSEC canonicalization is rebuilt per candidate RRSIG**
      (`rdns/src/dnssec.rs:779`, inside the loop at `:749`). `signed_data` re-runs
      `canonical_rdata` over the whole RRset for each candidate — a full
      `record.parse()` with `String` allocations, `canonical_name` per embedded
      name, re-encode via `dname_to_bytes`, then re-sort and re-dedup. An RRset
      signed by both a KSK and a ZSK does all of it twice for an identical result.
      Only `type_covered`, `original_ttl` and the owner via `labels` differ between
      candidates, and they almost always agree: compute the sorted/deduped RRset
      once and rebuild only the RRSIG prefix per candidate. (The verify primitives
      themselves are fine — RSA borrows slices with no allocation, and ECDSA's
      65-byte point prefix is forced by ring's API.)
- [x] **`serialization.rs` is dead code that documents a guarantee it does not
      implement — delete it** — **done 2026-07-28**, on the way past while typing
      the wire layer's errors: converting dead code to a better error type would
      have been work spent making a loaded gun more comfortable to hold. Its 11
      tests went with it, which is why the lib count drops from 578 to 567.
      Original finding follows. No caller anywhere outside its own `#[cfg(test)]`
      module. Its doc comment at `:112` promises RFC 4034 canonical ordering; the
      loop at `:116` emits in argument order and never sorts, and
      `serialize_resource_record_canonical` (`:53`) writes the owner via
      `dname_to_bytes` with **no down-casing**, so it does not produce §6.2
      canonical form either. It also allocates `vec![0u8; 65535]` *per record*
      plus a second ~64 KB temp inside — 128 KB per RR. The live canonicalization
      (`dnssec.rs::signed_data`) is correct and well-commented; this module is a
      loaded gun aimed at whoever wires it up, because a caller would get silently
      unverifiable signatures.
- [ ] **`bench.rs` measures debug builds and cannot see the defects above.** It is
      `#[cfg(test)]`-gated, so it does not exist in release builds and every number
      it prints is a debug number (`:351` says so). `bench_cache_throughput`
      (`:104`) only ever calls `get` on an empty cache, so it never reaches
      `evict_oldest` and cannot observe the O(n²) eviction at all. Worth converting
      to criterion benches under `benches/` so they measure optimized code, with
      cases that exercise what actually hurts: `log_query` at a realistic window
      depth, `put` into a full cache, and `to_bytes_within` on a full-size response.

#### 9f. Smaller conformance gaps found in the same pass

- [ ] **QCLASS is never checked or matched** (`rdnsd/src/main.rs:249`,
      `zone.rs:199`, `:238`). `ZoneRecord.class` is stored and parsed (IN/CH/HS)
      but never compared at lookup, so a CH-class query is answered from the IN
      zone — the question echoes `CLASS=CH` while the answer records carry
      `CLASS=IN`, a malformed pairing. Filter by class in `Zone::query`/`name_exists`
      and REFUSE a class the zone does not serve.
- [ ] **QTYPE=ANY (255) is answered as NODATA** — no stored record has rtype 255,
      so an existing name gets empty NOERROR + SOA, which is none of the three
      shapes RFC 8482 §4.1 permits. Either return every RRset at the name (plus
      RRSIGs when DO is set) or take §4.2's synthesized-HINFO route deliberately.
      The constant is already defined and unused at `rdns/src/utils.rs:55`.
- [ ] **Unknown QCLASS is aliased onto a meaningful class, and unknown RCODE is
      rewritten to 0** (`rdns/src/lib.rs:810`, `:940`).
      `QueryClass::from_u16(qclass).unwrap_or(QueryClass::None)` maps QCLASS 99 to
      NONE — which is 254, RFC 2136's *real* NONE class, not a sentinel — and it is
      re-serialized as 254 at `:973`, so the echoed question differs from the
      question asked. `ResponseCode` has an `Unknown` variant but `to_bytes` maps
      it to 0, so a relayed response with an unrecognized rcode becomes NOERROR,
      and the resolver does relay upstream messages. Fix both with a value-carrying
      catch-all (`Other(u16)`) so `to_u16` is infallible and round-tripping is
      total.
- [ ] **QNAME minimisation has no iteration ceiling** (`rdns/src/resolver.rs:1030`,
      `:1119`). RFC 9156 §2.3 requires a MAX_MINIMISE_COUNT, recommended 10, after
      which the full QNAME is sent. The loop deepens one label at a time for as
      many labels as the name has, so a reverse-IPv6 PTR (34 labels) costs ~30
      round trips and usually exhausts `query_budget` first — failing outright
      rather than degrading. Also worth taking §2.3's advice on QTYPE: the probes
      use NS (`resolver.rs:37`, `:1048`), which is RFC 7816's superseded guidance;
      A/AAAA are "least likely to raise issues in DNS software and middleboxes".
- [ ] **Glueless delegations are resolved with A queries only**
      (`rdns/src/resolver.rs:1259`, `qtype: 1`), so a delegation whose nameservers
      are IPv6-only and carry no glue is unresolvable — even though `query_server`
      correctly binds a v6 socket and `extract_referral` accepts AAAA glue.
- [ ] **`rdnsc` sends 512 bytes regardless of message length, and does not verify
      the reply** (`rdnsc/src/main.rs:22-31`). `to_bytes` returns `n` and it is
      discarded, so a 31-byte query goes out as 512 bytes with 481 trailing zeros —
      and this project's own `RequestValidator` caps UDP at exactly 512, so it is
      one option byte from rejecting its own client. `:29` mirrors the bug:
      `try_from_bytes(&buf)` on the whole receive buffer rather than `&buf[..n]`.
      It also never checks `msg.id`, the echoed question, or `msg.truncation`
      (so a truncated answer prints as complete, silently dropping records), has no
      TC→TCP fallback, no read timeout, and no retry. Separately, the server
      argument parses as a bare IPv4 — `rdnsc 127.0.0.1:15353 SOA example.com`
      fails with "invalid IPv4 address syntax", so our own client cannot query the
      non-53 port our own docs tell you to develop against. That is why every
      verification recipe above reaches for dnspython or Node.
- [ ] **A NOTIMP reply drops the client's OPT record** (`rdnsd/src/main.rs:242`
      returns before the EDNS mirroring at `:399`). RFC 6891 §6.1.1: if the query
      had an OPT, the response includes one. An EDNS client asking with an
      unsupported opcode gets a reply indistinguishable from a server that does not
      do EDNS, which some clients cache as a downgrade. `error_bytes` (`:921`)
      already does this correctly.
- [ ] **Truncated rate-limit replies set AA and hardcode 512**
      (`rdnsd/src/main.rs:948`, `:965`). `truncated_reply` ignores
      `msg.udp_payload_size()` (RFC 6891 §6.2.4) and sets `authoritive: true` on a
      reply carrying no authoritative data. `error_bytes` at `:918` gets AA right.
- [ ] **Zone transfer responses never carry an OPT record**
      (`rdns/src/transfer.rs:108`, `additionals: Vec::new()`). No known client
      fails on it, but RFC 6891 §6.1.1 applies to transfers too.

**Gaps found but deliberately not scheduled here** (unimplemented, not wrong):
DNAME (RFC 6672) is absent and unclaimed — `zone.rs:1130` rejects the type at
load; SRV, CAA, TLSA, SSHFP, NAPTR and SVCB/HTTPS have no named parser and can
only be loaded via RFC 3597 generic form (a *parser* gap — the unknown-type
pass-through itself is correct, `lib.rs:225` preserves opaque bytes and
`compression.rs:104` correctly refuses to compress names inside them);
`make_response` never populates `additionals`, so an MX answer carries no address
for the exchange (RFC 1034 §4.3.2 step 6) and every client pays a round trip;
no CDS/CDNSKEY (RFC 7344/8078), so parent-side automation is impossible;
EDNS options are dropped rather than echoed (`Edns::with_payload_size` builds an
empty list), so DNS Cookies are never returned and a cookie-enforcing client
re-queries over TCP forever; no edns-tcp-keepalive (RFC 7828) despite pipelining
being implemented with a hardcoded 10 s idle timeout; no root priming query
(RFC 8109), so `rdnsr` never learns the live root NS set; QDCOUNT > 1 is accepted
and half-handled by both servers where BIND and NSD answer FORMERR; and
`dnssec_answer.rs:248` documents the choice to read NSEC3 parameters off the
chain rather than NSEC3PARAM, so a pre-signed zone mid-salt-roll with two chains
is not served correctly.

---

### 8. What signing turned up

Three gaps, in the order they will bite. The first two are signing's own; the
third is older than signing and was only made visible by it.

- [ ] **Nothing re-signs a running server.** Signatures are made when a zone
      loads — startup, and SIGHUP where signals exist — and expire
      `--signature-validity` days later, 30 by default. A server up longer than
      that serves expired signatures, which is bogus rather than merely stale:
      every validating client stops resolving the zone. The workaround is a
      `kill -HUP` from cron and it is not good enough. The work is a timer that
      re-signs at roughly a third of the validity, which `sign_zone` already
      supports — it drops the previous run's output and starts over, so
      re-signing an already-signed zone is the ordinary case, not a special one.
- [ ] **Re-signing does not bump the SOA serial**, which is what the timer above
      has to decide before it can be written. New signatures are a new version of
      the zone as far as a secondary is concerned, and a secondary compares
      serials — so without a bump the replica keeps the signatures it transferred
      and they expire underneath it. With a bump, every re-signing is a zone
      change that NOTIFYs the world, which is what BIND does and what the
      replication path here is already built for (`install_all_zones` computes
      the delta, `announce_zones` sends it). The reason it is not done in the
      same breath as the timer is that a serial that moves on its own interacts
      with an operator editing the same number in the file, and that deserves
      deciding rather than defaulting.
- [x] **`rdnsd` answers NXDOMAIN where a referral belongs** — **done 2026-07-28
      as #9a's second bullet**, which is where the implementation notes are. The
      three items turned out to be one missing walk through RFC 1034 §4.3.2, as
      the note below predicted, and were done together. Original finding follows.

      A query for a name
      under a delegation finds no records at that name and falls through to
      `Zone::name_exists`, which says no — so a child zone's names are denied by
      the parent rather than pointed at. This is wrong without DNSSEC and *loudly*
      wrong with it: the denial is now signed, so the parent authenticates a
      statement that the child does not exist. The zone signer already computes
      the delegation set it would need (`zone_signer::Layout`), and the denial
      records for the secure and insecure cases already exist in the chain; what
      is missing is `make_response` noticing that the query name is below a
      delegation and answering with the NS RRset, its glue, and either the DS or
      a proof there is none.

      **Confirmed and extended by the review — see #9a.** The denial also goes out
      with **AA=1** (`rdnsd/src/main.rs:203` hardcodes it), which RFC 1035 §4.1.1
      forbids on a referral and which is what makes an RFC 8020 resolver cache the
      whole subtree as non-existent. Do this one together with #9a's CNAME and
      wildcard items: all three are the same missing walk through RFC 1034 §4.3.2,
      and they share the closest-encloser/delegation lookup.

### 7. The secondary role — replication, in six steps

`rdnsd` is a standalone primary: it reads zone files, serves them, hands out copies
(AXFR) and announces changes (NOTIFY). It cannot be the *other* end of any of that.
Adding the client half makes it a replica in a single-writer, asynchronous,
pull-based replication topology — one primary holds the editable copy, secondaries
are read-only, NOTIFY is a wake-up hint rather than a data channel, and there is no
election or conflict resolution because a replica never accepts writes. It also
composes: a secondary can serve AXFR of a zone it fetched and NOTIFY further
downstream, so one binary can be any node in a replication tree.

What the client actually does, per (zone, master): load the local copy and its last
refresh time → ask the master for the zone's SOA → compare serials (RFC 1982) →
transfer if behind (AXFR, or IXFR with our SOA in the authority section) → verify,
assemble, **swap in atomically** → persist → sleep on the SOA's REFRESH, RETRY and
EXPIRE, with a NOTIFY short-circuiting the wait. EXPIRE is the one with teeth: out
of contact past it, a secondary must **stop answering** rather than serve stale
authoritative data.

The steps, in decreasing value per line:

- [x] **1. Serve both transports in one process** — done, see "Done so far". The
      rate limiter, validator, logger and metrics are shared now, so a client cannot
      get two budgets by switching transport.
- [x] **2. A zone-file writer**, plus the write-temp-then-rename helper — done, see
      "Done so far" and "Architecture: writing a zone back out". `zone_writer` and
      `persist` are the two new modules; there is no CLI surface for dumping yet,
      because step 3 is the first caller and the flag belongs with it.
- [x] **3. Secondary role, AXFR-only** — done, see "Done so far" and "Architecture:
      the secondary role". `--secondary zone@master[:port][#key]`, new `xfr` and
      `secondary` library modules, the state sidecar, per-zone atomic swap, EXPIRE
      withdrawal, and a NOTIFY from a master now refreshes instead of being answered
      NOTAUTH.
- [x] **4. IXFR-out** from in-memory diffs computed at load time — done, see "Done
      so far" and "Architecture: incremental transfer". BIND's
      `ixfr-from-differences` semantics without an on-disk journal.
- [x] **5. IXFR-in** — done, see "Done so far" and "Architecture: incremental
      transfer". A refresh asks for the difference whenever it has a version to
      differ from, and copes with all three answers.
- [ ] **6. Persisted deltas**, only if dynamic UPDATE (RFC 2136) ever arrives — that
      is what really needs a journal, because then the journal *is* the source of
      truth between file syncs.
- [x] **A secondary announces what it transferred** — done, see "Done so far".
      `announce_zones` covered only the moments a *primary* learns of a change
      (startup, SIGHUP), so a tree below the first level moved on refresh timers.

**One simplification worth not re-deriving.** Applying a transfer does not need a
record-removal API on `Zone`, and it is worth never adding one: the index holds
*positions* into the record vector, so removal shifts every later position. A full
AXFR is "build a new `Zone`, swap it in". An IXFR delta is "build a new `Zone` from
the old records minus the deletes plus the adds, swap it in" — O(zone size) per
transfer rather than per record, which at any zone size this serves is nothing.

### 10. Dynamic UPDATE (RFC 2136) — the dependency nothing schedules

**Not planned, and deliberately listed anyway**, because three other places treat
it as a thing that will happen and defer real work to it. Before this entry
existed, every mention of RFC 2136 in the repo was a *reason for not doing
something else*:

- `ixfr.rs:16` — "A journal earns its keep when dynamic UPDATE arrives (#7 step
  6) and not before", which is the design rationale for computing deltas in
  memory instead of persisting them.
- #7 step 6 — "Persisted deltas, **only if** dynamic UPDATE ever arrives".
- "Current state" above, twice (now once).

`ixfr.rs` defers to #7.6, #7.6 defers to UPDATE, and nothing points at UPDATE. The
loop closes with no work item in it, which is how a load-bearing dependency stays
invisible. The only trace in the code is `lib.rs:598`, a comment labelling the
UPDATE-related RCODE constants — the wire format needs them, so they exist; the
opcode is answered NOTIMP by `rdnsd` (`main.rs:242`) and, per #9c, mishandled as
a query by `rdnsr`.

**Nothing here needs doing.** The in-memory-delta decision is correct on its own
terms — NSD answered AXFR as a primary for years — and stays correct as long as a
zone changes only in discrete events (a reload, or a transfer). The entry exists
so that a cold start reads "we chose not to, and here is what would change the
answer" rather than "someone forgot".

**What would change the answer:** a zone edited between file syncs. That is the
moment the journal becomes the source of truth rather than a cache of one, and
the moment "one writer per file" in "Architecture: persistence" starts doing real
work instead of describing a property that is currently free.

**If it is ever picked up**, roughly in order, and note that only the last step is
#7.6 — the journal is the small part:

- The UPDATE opcode itself: prerequisite-section evaluation (RFC 2136 §3.2 — the
  five prerequisite forms, each with its own RCODE), then update-section
  application (§3.4), then §3.7's rule that the whole update is atomic — all
  prerequisites are tested against the zone *before* any change is applied.
- Authorization per zone, on top of TSIG. §3.3 leaves policy to the
  implementation, and "any key may update any zone" is the same mistake #9d
  records for transfers — fix that one first and this inherits the shape.
- Serial handling, which collides with #8.2: an UPDATE bumps the serial, and so
  does re-signing, and both then have to survive a reload that re-reads a file
  saying something older. Do not design these separately.
- Re-signing the changed names only, rather than the whole zone — `sign_zone`
  currently rebuilds everything, which is fine at load and wrong per update.
- Writing the zone back out, which `zone_writer` already does, and then #7.6:
  the journal, so a restart does not lose changes that exist nowhere else.

Estimate, for planning against rather than committing to: **1.5–2 weeks** for the
whole of that, of which #7.6 is about a day. It is the largest single feature not
on this list.

### 5. Smaller open items
- [x] **AXFR** — done, see "Done so far" and "Architecture: zone transfer".
- [x] **TSIG** (RFC 8945) — done, see "Architecture: TSIG". A key authorizes a
      transfer from any address, and every signed query gets a signed answer.
      Neither `rdnsr` nor `rdnsc` signs anything yet: TSIG is server-side only, so
      there is no way to *send* a signed query from this workspace except from a
      test.
- [x] **NOTIFY** (RFC 1996) — done, see "Architecture: NOTIFY". `--also-notify`
      tells a secondary at once instead of leaving it to the refresh timer, and an
      incoming NOTIFY is answered as a NOTIFY.
- [x] **IXFR** (RFC 1995) — **done as #7 steps 4 and 5**, both directions. Left
      here with its original reasoning because the framing is what made it cheap:
      it is an optimisation
      inside the secondary story rather than a feature of its own. The thing worth
      knowing before starting there is that a server may *always* answer AXFR-style
      instead (RFC 1995 §4), which NSD did as a primary for years, so the conformant
      first version needs no journal at all. (The request used to be unreceivable —
      the validator rejected any request with a non-empty authority section, which
      is where an IXFR carries the client's SOA. Fixed while making NOTIFY work; see
      "Done so far".)
- [x] **Amplification** — the response byte budget is in (`--response-rate`, UDP);
      see "Done so far" and "Architecture: amplification". `rdnsd` still binds
      `0.0.0.0` by default, which is the right default for an authoritative server
      and the reason the budget matters.
      (Note: the resolver's outbound source port is already randomized via
      `UdpSocket::bind("0.0.0.0:0")`. Do **not** "fix" the servers to reply from
      a random port — a reply must come from the port the query was sent to.)
- [x] Plain RFC 2308 negative caching — done, see "Done so far". `rdnsr` still
      caches only the answer section of a *positive* answer: authority and
      additional records (delegation NS sets, glue) are dropped, so a referral
      learned mid-resolution is not reusable except through the delegation cache.
- [x] Zone parser: `$INCLUDE` and parenthesized multi-line records — done, see
      "Done so far". RFC 3597's `TYPEnnn` and generic `\# <len> <hex>` rdata are in
      too, since the writer needs them. Still missing from the parser: TTL unit
      suffixes (`1h`, `2d`), `\`-escaped dots inside a label, and `@` as an rdata
      name. The escaped-dot gap now has a consequence beyond reading: it is the one
      thing that can make a zone *unwritable*, since an owner name is the first
      field of the line and has no generic form to fall back to.
- [x] TXT `<character-string>` framing — done, see "Done so far".


## Closed work

Kept because the reasoning is the useful part — what was tried, what the RFC
actually required, and why the shape is what it is. The commit messages carry the
detail; these are the summaries worth having in front of you.

### 1. Recursor follow-ups — done
Aggressive NSEC caching (RFC 8198) landed; see "Architecture: aggressive use"
and "Done so far". Everything else under #1 — async conversion, QNAME
minimization, 0x20 + reply validation, RTT-based server selection, IPv6
hints/glue and the `--root-hints` flag — was already done.

The recursor is covered by 51 tests in `resolver.rs` (see "Architecture: the
resolver") and the denial cache by 16 in `nsec_cache.rs`.

Two things aggressive use deliberately does **not** do, either of which is a
reasonable next step:

- [x] **Wildcard synthesis** (RFC 8198 §5.3) — done, see "Done so far" and
      "Architecture: aggressive use". A validated wildcard answer is kept under the
      wildcard and answers for other names it reaches.
- [x] **NSEC3's NXDOMAIN path is now resolved end to end** — the signed test
      hierarchy serves an NSEC3-proved NXDOMAIN, and the resolver validates it
      Secure through the whole path: collected across hops, parsed off the wire,
      and verified as an RRset at owner names that are base32hex of a hash. The
      companion test removes the closest-encloser record and requires the verdict
      to stop being Secure, since a proof that only *covers* the name would
      otherwise let one covering record deny anything in the zone.

### 2. DNSSEC follow-ups
Validation is on the resolve path and enforced (see "Architecture: DNSSEC" and
"Done so far"). What is left is narrower than what landed:

- [x] **RFC 5011 automated key rollover** — done, see "Done so far" and
      "Architecture: following a trust anchor". `rdnsr --auto-trust-anchor <file>`
      follows the zone's own signed DNSKEY RRset, adopts a successor after a
      30-day hold-down, and drops a key that revokes itself.
- [x] **CNAME chains are validated as chains** — done, see "Done so far" and
      "Architecture: DNSSEC". `dnssec_chain::cname_chain_shape` walks the answer
      from the question and requires every record to be on that path; a Secure
      verdict now depends on it.
- [x] **`rdnsd` signs a zone** — done, see "Done so far" and "Architecture:
      signing a zone". `--generate-keys` makes a KSK and a ZSK and prints the DS
      for the parent; `--signing-key-dir` signs every zone there is a key for as
      it loads; `--nsec3` picks the other chain. `dnssec_validation_mode` is
      what checks the result before it is served.

### 3. NSEC3 salt and iterations — done
Was: `validate_nsec3` hashed the query name with a single bare SHA-1 pass,
ignoring the salt and iteration count it had already parsed. Now
`dnssec_denial::nsec3_hash` implements RFC 5155 §5 properly and is checked
against the RFC's own Appendix A vectors. Iterations are capped at 150
(RFC 9276); above that the hash is refused, which reads as insecure rather than
bogus — a zone that signs itself unreasonably is not evidence of an attack.

### 4. Zone lookup — done
Was: `Zone::query` filtered the whole record vector per query, and `matches_query`
normalized and lower-cased both names into fresh `String`s for every record it
touched — 20k allocations for one lookup on a 10k-record zone, measured at
**4.4 ms**. Now indexed by owner name at load time: **0.685 µs**, and
`bench_zone_lookup` guards the regression. See "Architecture: zone storage".

### 6. Special-use names in `rdnsr` — done

- [x] **`localhost`** resolves to 127.0.0.1 / ::1 and never goes upstream
      (RFC 6761 §6.3), the whole subtree included.
- [x] **`*.local`** is answered NXDOMAIN at once (RFC 6762 §3).
- [x] **Private-address reverse lookups** are answered locally (RFC 6303 §4),
      including the sixteen zones 172.16/12 really is and the v6 equivalents.
- [x] **`invalid.`** is NXDOMAIN (RFC 6761 §6.4); the `example.` names are left
      ordinary, which is the only thing they exist for.

See "Done so far" and "Architecture: names that never leave".

**The rest of that ambition is deliberately not on this list**, because it is not
DNS: dynamic upstreams and per-link split DNS from DHCP/NetworkManager/
systemd-networkd (reconfiguring live when a VPN or a new Wi-Fi network appears),
mDNS/LLMNR responding, DNS-over-TLS, a `resolvectl`-style control surface
(flush-caches, statistics), privilege dropping and a systemd unit, and listening
on 127.0.0.1 *and* ::1 at once — `rdnsr` binds one host:port
(`rdnsr/src/main.rs:204`). That is a network-configuration daemon that happens to
speak DNS, and it is a bigger project than this one. Smaller gaps in the same
direction, if it is ever picked up: no opcode check (an UPDATE or NOTIFY is
treated as a query rather than answered NOTIMP), no admission control on the UDP
path (a task per datagram, unbounded — TCP has both caps), no rate limiting or
query logging in `rdnsr` at all (both exist in the library, wired into `rdnsd`
only), no signal handling, no EDNS cookies (RFC 7873), and static root hints with
no periodic re-priming of the root NS set.

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

That run is also what caught the two bugs under "Done so far" that no unit test
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

`rdnsr` (`rdnsr/src/main.rs`): query → EDNS sanity check (FORMERR / BADVERS) →
`DnsCache` lookup → miss resolves by awaiting `Resolver::resolve` (async; each
upstream round trip is an `await`, no blocking thread) →
cache-store by (name,type)+TTL → reply, echoing the client's txn id with RA set
and OPT mirrored only if the client used EDNS. Cache hits return in 0 ms against
~7 ms for a miss.

It serves UDP *and* TCP on one host:port — both loops are spawned and whichever
fails first takes the process down, so it never silently serves one transport.
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

## Done so far

Newest first. The reasoning, RFC citations and verification for each are in the
commit message.

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

`dname` owns the primitives — the bounds-checked write, the label encoder, and
the pointer constants. `compression` holds only the per-message offset table and
the policy for which RR types may have compressed names in their RDATA.

```rust
dname_to_bytes("www.example.com.")?     // full, uncompressed — RDATA and DNSSEC

// One compressor per message being serialized; offsets are meaningless across
// messages. DnsMessage::to_bytes drives this for you — you only touch it
// directly if you write a new serializer.
let mut c = NameCompressor::new();
pos = c.write_name("www.example.com.", buf, pos)?;   // literal, or a pointer
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
secondary::is_newer(remote_serial, ours);       // RFC 1982, never `>`

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
