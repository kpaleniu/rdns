# rdns — TODO / Next Steps

Working notes for picking this up cold. **`CLAUDE.md` is the companion to this
file**: this one says where the work is and how to run it, that one says which
mistakes this codebase has already made and the rules that follow from them.
Read both before planning; the first rule in `CLAUDE.md` is why a green suite
here has twice not meant what it looked like.

**Starting cold, read in this order:** "Current state" for what works today and
what is unproven, "How to run" for the commands, the four environment traps under
"Verifying" (each has cost an hour) plus the Linux recipe beside them for anything
`#[cfg(unix)]` or containerized, and then "Where to pick up next". The
"Architecture" sections describe what exists and why it is shaped that way — they
are the part of this file that is not written down anywhere else. Finished work
is one line each under "Done so far", pointing at the commit that carries its
reasoning, RFC citations and verification.

**The short version, if you read nothing else:** **every numbered item through
#14 is closed.** The operational
shell is finished; #9's five-way review went in full, its last performance item
closed by measuring rather than fixing it; #12's audit found no reachable panic
and left a fuzzer behind to keep it that way; and **#13 moved five families of
invariant out of per-call-site checks and into the types, in twelve commits,
fixing seven live defects on the way** — an opcode field that rewrote eleven of
its sixteen values, a QTYPE=ANY answer that SERVFAILed a good signature, two OPT
records where RFC 6891 requires FORMERR, an escaped dot encoded as two labels,
two distinct wire names collapsing onto one string, a fifth copy of the ANY rule,
and `rdnsd` answering a response sent to its UDP port. What is left is a stretch
goal (#11), a feature nobody has scheduled (#10), three candidates (#14),
and the first thing worth doing: **CI runs now, and its first run failed.** Build
and test with the four commands at the top of `CLAUDE.md`; `cargo bench -p rdns`
is the fifth. **Do not push** — commit locally and leave it; every push spends
the owner's GitHub Actions minutes on a private repository. Nothing is
half-applied and the tree is clean.

**This file was cut from 6,067 lines to about a third of that on 2026-08-02**,
when the last numbered item closed. What went was the full text of findings that
are now fixed — 55 "original finding follows" blocks and a 2,435-line review
section — because that reasoning is in three better places: the commit that fixed
each one, the rules distilled in `CLAUDE.md`, and `git log -p TODO.md`, which
still has every word of it. What was kept is what a cold reader cannot get
elsewhere: how to run the thing, why it is shaped as it is, and which claims on
this page turned out to be wrong.

---

## Current state (last updated 2026-08-02)

**Workspace** — five members, all on branch `main` (it was `master` until
2026-08-01; the rename is why older commit messages say the other one):

| crate     | what it is                                                        |
|-----------|-------------------------------------------------------------------|
| `rdns`    | the library: wire codec, zones, cache, resolver, DNSSEC           |
| `rdnsc`   | command-line query client                                         |
| `rdnsctl` | control client for a running `rdnsd`: `status`, `reload`, `dump` (Unix only) |
| `rdnsd`   | authoritative server — serves zone files over UDP and TCP in one process |
| `rdnsr`   | recursive resolver with a caching layer; forwards on `--upstream` |

**There is a remote, and CI has run at last (2026-08-01).** `origin` is
The remote is **private**, and
`.github/workflows/ci.yml` finally has somewhere to execute. Seven job-runs per
push — `test` on Linux *and* Windows, plus lint, msrv, deny, image and features —
of which the Windows leg bills at twice the rate against the free-tier allowance.
`concurrency` with `cancel-in-progress` is set, so a second push abandons the
first run rather than paying for both.

**Do not push from a session.** Commit locally and stop; the owner pushes when
they choose to. This is why: the account has a cap, and a session that pushes on
every commit spends it on runs nobody asked for.

**The first CI run failed, and the failure was the test's fault rather than the
code's.** One job failed and one warning appeared across several; both are fixed
locally and unpushed, and nothing was wrong with the code CI was checking. The
Windows `build and test` job failed
`a_reload_does_not_hold_the_write_lock_across_its_diffs` at 71% of samples locked
out, where this machine measures 0.3% for the same code. `tokio::sync::RwLock` is
fair, so `try_read` fails while a writer is merely *queued*: the metric was
measuring scheduler wake latency, and its denominator was the sampler's own spin
rate, which is not a clock. The test measures a window of *time* against a
baseline diff it times on the machine it is running on now. Fixed and verified
both ways under starvation (`59cc900`).

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
inside it, the commit references in "Done so far" and the entry in
`.git-blame-ignore-revs` were remapped by matching subjects, and every one
resolves. The blame file is the one that would have failed loudly rather than
quietly — `git blame` refuses a revision it cannot resolve.

**Green as of the last commit**, on both platforms and checked on both:

| | Windows | Linux |
|---|---|---|
| `rdns` lib | 648 | 633 |
| allocations | 1 | 1 |
| no_input_panics | 1 | 1 |
| `rdnsd` | 94 | **106** |
| `rdnsr` | 3 | 3 |
| **total** | **747** | **744** |

**The Windows column is current and the Linux one is not.** Linux was last
measured before #13 landed; the gap between the columns is the sixteen
`#[cfg(unix)]` tests below plus whatever has been added since, and it is no
longer safe to read it as only the former. Re-run the Linux recipe under "Running
the Linux half by hand" before quoting the right-hand column.

**Two of those single tests are worth more than their count suggests.**
`allocations` reports **nineteen** measurements, **thirteen** of them exact
(`n..=n`) — the earlier claim of "fourteen exact" on this page was never counted
and was wrong both ways; five are deliberate ranges and one
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
because it is not obvious: `dhat` counts calls into the global allocator, so what
it measures does not depend on whether glibc's malloc or Windows' heap is
underneath. Every exact assertion in `rdns/tests/allocations.rs` (0, 1, 2, 2, 3,
3 and 4) reads the same on the Linux side.

`cargo clippy --workspace --all-targets` and `cargo fmt --all --check` are clean
**on Windows**; the Linux image used for the Linux runs has no clippy package,
so that half is checked by CI now and was checked nowhere before.

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
the numbers are the input to any future attempt: **13.7 allocations per query**
for a plain query (down from 25.7), **20.7** for the query a real resolver sends
(EDNS0, DO, a cookie). One whole answer — parse, look up, build, serialize — is
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

# The container image. Never built on this machine (no runtime here); the `image`
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

### Running the Linux half by hand

CI covers this now, but a session still cannot push (see "Current state"), so
this is how the Linux half gets checked before a commit rather than after one.
This is a Windows machine, so anything `#[cfg(unix)]` is invisible here — that is
how `rdnsd` went months without compiling on Unix. **The Linux image
has a full toolchain** (cargo, rustc, gcc) and is where every Linux number in
this file comes from:

```sh
# Copy the tree in. Excluding target/ matters: it is large, and a Windows
# target/ is useless to a Linux build anyway.
rm -rf "$SCRATCH" && mkdir -p "$SCRATCH" \
  && cd "$REPO" && tar cf - --exclude=target --exclude=.git . \
  | (cd ~/rdns && tar xf -)"
cargo build --workspace --all-targets && cargo test --workspace
```

**That image also has docker** (29.6.2), which is where the container image was
built and exercised before CI's `image` job existed to do it on every push. The
user is in `wheel` and not `docker`, so every command needs `sudo -n`:

```sh
sudo -n docker build -t rdns:local \
  --build-arg RDNS_GIT_DESCRIBE=$(git describe --always --dirty --tags) .
```

The build arg matters: the build context has no `.git` in it on purpose, so
without it the image reports a bare `0.1.0`.

Three things to know before trusting a run there:

- **Build on a native filesystem, not the mount.** It reports everything as 0777 and
  `chmod` is a no-op without the `metadata` mount option, so every
  permission-related test would either pass or fail for reasons that have
  nothing to do with the code. `~` is ext4 and behaves.
- **That image has no `clippy`.** `cargo clippy` fails with "no such command", so
  the lint half of the four commands is Windows-only for now.
- **The copy is a copy.** Re-sync before each run or you are testing whatever was
  there last time; the tar line above is cheap enough to repeat.

One older image has cargo but **no C compiler**,
so every build there dies at `linker \`cc\` not found` — ring needs one. Use
the Linux image.

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

**The checks CI runs, to run before pushing.** All five pass as of the last
commit; the first four are `CLAUDE.md`'s and the fifth is new with CI:

```sh
cargo build --workspace --all-targets
cargo test --workspace                          # 603 + 6 + 85 + 2
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check                                # needs cargo-deny 0.17+
```

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

The numbers are **stable identifiers, not reading order.** They are referenced
from the code (`ixfr.rs:16` points at "#7 step 6") and from each other, so they
are never renumbered.

**Everything numbered through #13 is closed; #14 is filed and unstarted.** What
each was, and where its reasoning now lives — the commit that closed it, and the
rule it became in `CLAUDE.md`:

| # | what it was | closed |
|---|---|---|
| **1-4, 6** | recursor, DNSSEC and NSEC3 follow-ups, zone lookup, special-use names | see "Closed work" below |
| **5** | smaller items: AXFR, TSIG, NOTIFY, IXFR, amplification, negative caching, `$INCLUDE`, TXT framing | all done; see "Done so far" |
| **7** | the secondary role, in six steps | 5 of 6 done; step 6 (persisted deltas) waits on #10 and is the one unchecked box in this file |
| **8** | what signing turned up — the re-signing timer and its serial | done |
| **9** | what a five-way review found: 48 defects in six groups (9a-9f) | **all done, 2026-07-27 → 2026-08-01.** The patterns became `CLAUDE.md`, which is the useful artefact; the 2,435 lines of finding text are in `git log -p TODO.md` |
| **10** | dynamic UPDATE (RFC 2136) | **started 2026-08-02.** The reading half is in (`rdns/src/update.rs`: §2.4/§2.5 forms, §3.1, §3.2, §3.4.1's prescan); the writing half — apply, serial, re-signing, journal — is not. #7 step 6 still waits on it |
| **11** | data layout and CPU cache friendliness | **a stretch goal, not scheduled.** Its measurement harness exists now (criterion, `--baseline`); what it still lacks is the *diagnostic* half — `perf stat`'s cache-miss and branch-miss counters, which this Windows machine cannot read. `zone/miss in a 10k-record zone` (159 ns) is the number it would have to move |
| **14** | three candidates #13 left on the table: `Serial`, QR as a type, sealing `RecordData` | **all three done 2026-08-02**, one commit each. 14a removed the second copy of RFC 1982 §3.2 and made `a > b` on two serials a compile error; 14b put all three socket entry points behind one `Request` door; 14c sealed `RecordData` into its own module — and, by asking what invariant it actually holds, found that a legal RFC 2136 UPDATE could not be parsed at all. 14a and 14b are preventative and say so; 14c's finding is under #10, with a regression test watched failing |
| **12** | pre-authentication panics | **audited 2026-08-01.** No reachable panic in 1.4M mutated inputs; two mutex-poisoning fixes; `rdns/tests/no_input_panics.rs` left behind as the guard |
| **13** | making illegal states unrepresentable: `OpCode`'s sentinel, the eleven name normalizations, QTYPE-vs-RTYPE, `Ttl` + `Class` + OPT out of the additional section, `Name`/`NameKey` | **done 2026-08-02**, twelve commits. 13a-13d in full; 13e's map keys done and its `Name` half deferred with a reason. Seven live defects fixed on the way. Every stage gated on `rdns/tests/allocations.rs` and every one has held its counts; 13b added a fifteenth measurement that went 2 to 0 |

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

**One decision is the copyright holder's, not a bug:** the manifests say
`MIT OR Apache-2.0` and the repository ships only an MIT `LICENSE`. Either add
`LICENSE-APACHE` or narrow the manifests. `cargo deny` passes either way.

### Where to pick up next

**#14 is closed.** All three candidates landed on 2026-08-02, and 14c turned
up a live defect in #10 on the way. Everything here is a choice rather than a
queue.

> **1. Push, and read the second CI run.** Everything the first one reported is
> fixed locally and unpushed. There were two findings, not three:
>
> - **The Windows `build and test` job failed**
>   `a_reload_does_not_hold_the_write_lock_across_its_diffs`, and the test was
>   wrong rather than the code. Fixed in `59cc900`; the reasoning is in "Current
>   state" and in the test's own doc comment.
> - **`actions/checkout@v4` targets Node 20**, which the runner now forces onto
>   Node 24. Bumped to `@v5` across all six jobs in the same commit. This warning
>   appeared in more than one job's log — including `licences and advisories`,
>   which is what that job is *called*; `cargo deny` itself passed. Worth knowing
>   before reading a log: a job name here describes what it checks, not what it
>   complained about.
>
> Five jobs have still never actually been read: msrv (1.95), deny, the container
> image, the `dhat-heap` feature build, and clippy on *Linux* — the Linux
> image has no clippy package, so that half had only ever run on Windows. They
> may have passed silently; nobody has looked.
>
> **2. #10, dynamic UPDATE (RFC 2136)** — and it is more urgent than it was.
> The reading half is in and, until 2026-08-02, could not be reached from the
> wire at all: an RDLENGTH=0 record made the whole message FORMERR before
> `update.rs` ran (see §10). That is fixed, so the writing half now builds on
> something shown to work end to end rather than only in memory. Read §10 first
> — it says which four of the six original items are still on the far side of
> the seam, and the serial one has to be designed together with #8.
>
> **#14 is closed** — 14a (`Serial`), 14b (`Request`) and 14c (sealing
> `RecordData`) all landed on 2026-08-02. See §14.
>
> **3. #10, dynamic UPDATE (RFC 2136)** — **started, one piece in.**
> `rdns/src/update.rs` reads an UPDATE and checks its prerequisites; nothing
> applies one yet. The next piece is applying the changes, and it must be
> designed together with the serial: an UPDATE bumps it and so does re-signing
> (#8), and both then have to survive a reload that re-reads a file saying
> something older. Read §10 below before starting — it says which four of the
> six original items are still on the far side of the seam.
>
> **4. The rest of #13 (13b-13e)** — subtraction first (13b deletes six
> duplicate normalizations, including a `to_lowercase` in the public API that
> §8 forbids), then the two zero-cost newtypes, then the deep one. 13d is where
> the work is: OPT comes out of the additional section, which is what lets the
> TTL clamp move to the parse boundary, and the two halves land in that order
> because the second is only correct after the first.
>
> **5. #11, cache locality** — wanted, but blocked on hardware counters this
> machine cannot read. Its harness is ready. Note that **#13e deliberately stops
> short of this**: a `Name` with inline or wire-format storage is #11's question,
> and doing both at once means neither measurement can be read.

**Read `benches/answer_path.rs`'s header before quoting anything from it.** One
whole answer is 522 ns and one `sendto`+`recvfrom` pair is 4 µs, so the entire
benchmark suite covers about 6% of what a query costs — the context that stops a
20% win in it being reported as a 20% win.

### 7. The secondary role — five steps done, one waiting

Steps 1-5 are done: both transports in one process, a zone-file writer with
write-temp-then-rename, the secondary role with `--secondary
zone@master[:port][#key]`, IXFR-out from in-memory diffs, and IXFR-in. See
"Architecture: the secondary role" and "Architecture: incremental transfer" for
the shapes, and "Done so far" for the commits.

- [ ] **6. Persisted deltas**, only if dynamic UPDATE (RFC 2136) ever arrives —
      that is what really needs a journal, because then the journal *is* the
      record of what happened rather than something recomputed from two versions
      that are both still in memory. `ixfr.rs:16` points here. Until then a
      restart forgetting its deltas is correct, permitted unconditionally by
      RFC 1995 §4, and self-correcting: the next change after a restart has a
      delta again.

### 10. Dynamic UPDATE (RFC 2136) — started 2026-08-02, one piece in

**The reading half is done and the writing half is not.** `rdns/src/update.rs`
turns an UPDATE message into a checked list of prerequisites and changes and
evaluates the prerequisites against a zone. It never mutates a zone, touches a
file, bumps a serial or looks at a key.

That seam was chosen rather than found: of the six things listed below, four are
policy or persistence, and all four sit on the far side of "here is what this
message would change" — which is also the shape a journal entry (#7 step 6) and
an IXFR delta both want. What is in:

- **§2.2's renamed sections**, which needed no wire work at all: question is
  Zone, answer is Prerequisite, authority is Update, additional stays itself.
- **§2.4's five prerequisite forms and §2.5's four update forms**, each keyed on
  CLASS — the field that says what kind of data a record is, used to say what to
  *do* with it. `QueryClass::None` being a real value with a real meaning here is
  why `CLAUDE.md` §2 insisted the parse keep it rather than fold it onto a
  sentinel.
- **§3.1's zone-section checks** (one zone, and it is an SOA), **§3.4.1's
  prescan** (no meta-type may be added; nothing outside the named zone, which is
  NOTZONE and not REFUSED), and **§3.2's four rcodes**, one per prerequisite
  form. They are not interchangeable: a client uses them to tell "the name is not
  there" from "the name is there and this type is not".

**A defect found on 2026-08-02, after the reading half landed: none of this
could be reached from the wire.** RFC 2136 spells six of its ten forms — §2.4.1,
§2.4.3, §2.4.4, §2.4.5, §2.5.2 and §2.5.3 — as a record with **RDLENGTH=0**, a
TYPE naming what the condition or deletion is about and no value.
`ParsedRecord::decode` rejected an empty RDATA for every type it had a decoder
for (an A with no bytes is four bytes short), and `RecordData::from_wire` runs
per record while the message is being read, so **the whole UPDATE was FORMERR at
the wire layer before `update.rs` ran at all**. Every value-independent
prerequisite and every RRset deletion was unreadable.

Nothing caught it because every test in `update.rs` hands `parse` a `DnsMessage`
built in memory — the boundary a real message crosses was the one thing never
exercised, which is `CLAUDE.md` §1 from a new direction: not a test that agrees
with the code, but a test that never reaches the code that disagrees. The fix is
in `ParsedRecord::decode` (empty RDATA is `Unknown`, kept verbatim, per RFC 3597
§5) and the regression test is
`update::tests::an_update_survives_the_wire_including_its_empty_rdata`, watched
failing against the old decoder. It was turned up by #14c asking what invariant
`RecordData` actually holds — the answer being that "well formed for its TYPE" is
not true on the wire, and RFC 2136 is where it is not.

Two rules in it are the kind that pass a careless test, so each was watched
failing against the careless implementation before it landed. §3.2.3 compares a
value-dependent prerequisite against the **whole RRset as a set** — "does the
RRset contain this record" is the obvious reading and is wrong, and `www` with
two A records is the case that shows it. And §2.4.4's "name is in use" is
`holds_name`, the literal "are there records here", not `name_exists` — which is
true for a name a wildcard reaches and for an empty non-terminal, so an update
would otherwise believe a name exists because something could synthesize it.

**What is left is the writing half**, and the four items below that this
deliberately stopped short of. Applying the changes is `ixfr::apply_changes`'
shape; what it drags with it is the serial, and that is the one that must not be
designed alone. The six original items follow.

Estimate for what remains: the bulk of the original **1.5-2 weeks**, since the
part now done is the part with no policy in it.

- The prerequisite section (§2.4), which is a small query language of its own and
  is checked against the zone *before* any change is applied.
- Authorization per zone on top of TSIG. §3.3 leaves policy to the
  implementation, and "any key may update any zone" is the mistake #9d records
  for transfers; that one is fixed, and this inherits its shape (`CLAUDE.md` §16).
- Serial handling, which **collides with #8**: an UPDATE bumps the serial and so
  does re-signing, and both then have to survive a reload that re-reads a file
  saying something older.
- Re-signing the changed names only, rather than the whole zone — `sign_zone`
  rebuilds everything, which is right at load and wrong per update.
- Writing the zone back out, which `zone_writer` already does.
- Then #7.6, the journal, so a restart does not lose changes that exist nowhere
  else.

### 11. Data layout and CPU cache friendliness — a stretch goal, on purpose

Wanted because it was asked for, not because a measurement demanded it. The
zone index is a `HashMap<String, Vec<usize>>` into one record vector; the
question is whether a layout with fewer pointer chases per lookup is worth
having.

**The prerequisite is met and the blocker is not.** `cargo bench -p rdns` with
`--save-baseline`/`--baseline` can now judge a single-digit-percent change, which
is what this needs and what `bench.rs` could never give. What is still missing is
the *diagnostic* half: cache misses and branch mispredicts per query, which means
`perf stat` on Linux, since the Windows box this was developed on has no
equivalent worth trusting. Without it, any change here is a guess with a
stopwatch attached.

`zone/miss in a 10k-record zone` (159 ns) is the number it would have to move,
and "Current state" has the context that decides whether moving it matters: the
whole answer is 522 ns against a 4 µs syscall pair.

### 12. Pre-authentication panics — audited 2026-08-01

**No reachable panic.** `rdns/tests/no_input_panics.rs` puts mutated wire data
through everything a stranger's bytes reach before a MAC has been verified —
`validate_packet` on both transports, `try_from_bytes`, the TSIG scan, both EDNS
readers, the zone lookups, `dnssec_answer`'s four proof builders against an
NSEC3-signed zone, and serialization back out. 1,506 cases in the suite,
1.4 million across four seeds for the closing commit.

Three things about it are deliberate and will be undone by accident otherwise:
it runs in a **debug** build, because overflow panics in debug and wraps in
release; it **mutates valid messages** rather than generating random bytes, since
random bytes never get past the header check; and it is hand-rolled rather than
`proptest`, because the corpus had to be built out of this library either way and
the seed is what makes a failure reproducible.

**What it found was the amplifier, not a panic.** `DnsCache` used
`.lock().unwrap()` on all four lock sites, two on `rdnsr`'s query path, and mutex
poisoning is permanent — one panic under that lock, ever, would make every later
query panic too. All four degrade now. `RateLimiter`'s two monitoring functions
had the same shape. See `CLAUDE.md` §6.

**Not covered:** the fuzzer drives the library primitives `rdnsd::make_response`
composes, but not the composition, because the mutator lives in an integration
test and `rdnsd` is a binary. Sharing it would ship a fuzzing mutator in every
release build.

**And the trade it was opened to re-ask stands.** A panic on the answer path ends
the process rather than being swallowed by a per-datagram task. The path is
fuzz-clean with a permanent regression test, so the trade costs nothing today,
and the alternative — respawning a panicked worker and counting it — would turn a
defect into a metric nobody reads.

### 13. Making illegal states unrepresentable — planned 2026-08-02, nothing landed

**The argument is an asymmetry in this repo's own history, not a preference.**
Of the defects `CLAUDE.md` records, two were fixed by *changing a type* —
`QueryClass::Other(u16)` and `ResponseCode::Other(u16)`, both replacing a
sentinel that could not carry what it stood for — and neither has come back.
Every other fix in the same class was a correction applied *at a call site*: the
TTL clamp, the ANY comparison, the case folding, the class check. Those keep
reappearing, one module at a time, because the next call site is written by
someone who has not read the last one. §2 already says this out loud — "if a
value has an invariant, make it unrepresentable without it rather than
re-asserting it per site" — and then the codebase re-asserts it per site
fourteen times for TTLs alone.

So this is not new work so much as finishing the shape of work already done. It
is also, deliberately, **not a rewrite**: the four conflations below are each a
newtype or an enum variant over a primitive that is already there, and three of
the four are provably zero-cost. The one that is not — 13d — buys a malformed
state that is currently representable and ten linear scans that currently run
per message.

**What this deliberately does not do**, so the scope does not creep:

- **No `Name` with inline or wire-format storage.** A 255-byte inline buffer or
  a length-prefixed wire form would beat `String` on cache locality, and that is
  #11's question, not this one. Doing both at once means neither's measurement
  can be read.
- **No typestate on the answer path.** "A response that has had its OPT mirrored"
  as a distinct type from one that has not would catch §7's early-`return` bug,
  and it would also make every function in `rdnsd` generic over a marker. Not
  worth it for one bug that now has a test.
- **No `Zone` generic over class.** The zone parser refuses non-IN records, which
  is what makes the class-blind index correct. Encoding that in a type parameter
  would be honest and would buy nothing, because there is exactly one instantiation.

#### How every stage is proved not to have cost anything

This is the gate, and it comes first because it is the thing that decides whether
a stage lands. Each stage is measured **before and after, on the same machine,
in the same session**:

```sh
cargo test -p rdns --test allocations -- --nocapture   # 18 counts, 12 exact
cargo bench -p rdns -- --save-baseline before          # then do the stage
cargo bench -p rdns -- --baseline before
```

**The allocation counts are the real gate.** They are exact, they do not care
what else is running, and `TODO.md`'s "Current state" records that they read the
same on Windows and on the Linux side — `dhat` counts calls into the global allocator, so
the number does not depend on which malloc is underneath. The bar is **identical
counts, or lower**. A count that moves up may not be waved through as noise,
because it cannot be noise; it may only be accepted with the reason written next
to the assertion, which is `CLAUDE.md` §10's rule about never lowering a floor
without proving why it moved, pointed the other way.

Criterion is the backstop for anything that trades an allocation for time. Read
`benches/answer_path.rs`'s header before quoting any of it: one whole answer is
522 ns against a 3.6-4.1 µs `sendto`+`recvfrom` pair, so the entire bench suite
is about 6% of what a query costs a server. Nothing in this section should be
reported as an end-to-end win.

#### 13a. `OpCode` is the third sentinel, and it is live — **done**

**Verified by provoking it**, not by reading the derive. A probe over all
sixteen opcodes, parsed with `DnsMessage::try_from_bytes` and serialized back
with `to_bytes`:

```
opcode  3 -> Unknown -> 15  CHANGED
opcode  6 -> Unknown -> 15  CHANGED     (and 7, 8, 9, 10, 11, 12, 13, 14)
```

**Eleven of sixteen opcodes are rewritten on the way out.** `OpCode` still has
an `Unknown = 15` sentinel and is still parsed at `lib.rs:1118` as
`OpCode::from_u8((hi >> 3) & 0x0f).unwrap_or(OpCode::Unknown)` — the exact line
§2 describes twice and calls the smell.

**Opcode 6 is DSO, and that is what makes this concrete rather than
prophylactic.** Checked against the IANA DNS OpCodes registry rather than from
memory: 0 Query, 1 IQuery (obsolete), 2 Status, 4 Notify, 5 Update and **6 DNS
Stateful Operations (RFC 8490)** are assigned; 3 and 7-15 are Unassigned. So a
DSO-capable client — and this codebase already knows DSO exists, it carries
`ResponseCode::DsoTypeNotImplemented` for RFC 8490's rcode 11 — sends opcode 6
and gets a reply saying opcode 15.

It reaches the wire. `rdnsd`'s `make_response` sets `opcode: msg.opcode`
(`main.rs:428`) and the NOTIMP branch fifty lines down echoes it. RFC 1035
§4.1.1 says that field "is set by the originator of a query and copied into the
response", and `CLAUDE.md` §8 already carries the rule — "The opcode is the
client's. Echo it" — which the code obeys for the five opcodes it has names for
and breaks for the sixth that exists plus the nine that do not yet.

- Replace with `Other(u8)` and hand-rolled `from_u8`/`to_u8` that are each
  other's inverse over all sixteen values, exactly as `QueryClass` and
  `ResponseCode` are over their range. `Query`, `IQuery`, `Status`, `Notify` and
  `Update` keep their names; nothing that matches on them changes.
- **This removes the last `num_derive` user in the workspace.** `lib.rs:2-3` are
  the only imports of it, so `num-derive` and `num-traits` come out of
  `rdns/Cargo.toml` with it. §14's rule about a dependency that does not do
  anything at run time applies: the derive's whole contribution here was the
  `Option` that invited the `unwrap_or`.
- **Regression test:** the probe above, asserting every one of the sixteen values
  round-trips. It fails against today's code for eleven inputs, which is the
  §1 requirement — watch it fail, then fix it.
- Cost: none. Churn: one enum, one parse site, one serialize site.

**Done.** Landed as planned, with three corrections worth keeping:

- **`Other(u8)`, not `Other(u16)`** as the plan first wrote it. OPCODE is a
  four-bit field; a `u16` payload would have made a value the wire cannot carry
  representable, which is this section's own mistake in miniature.
  `from_u8` masks to four bits, so the invariant is established at the boundary
  once (§2) rather than re-checked when the byte is packed.
- **"`num-derive` and `num-traits` come out" was half right.** Both lines left
  `rdns/Cargo.toml`, and `num-derive` left the dependency graph entirely — but
  **`num-traits` is still in `Cargo.lock`**, pulled in by `criterion`. It is a
  *dev*-dependency: `cargo tree -p rdns -e normal` has no `num-*` in it at all,
  so nothing ships in a binary. The lock went **144 → 143**, and the one entry
  that left was `num-derive` — measured with
  `git show HEAD:Cargo.lock | grep -c '^\[\[package\]\]'`, because the first
  number written here was a guess and was wrong. The saving is one crate
  compiled at build time, not a smaller shipped graph. Claiming a dependency
  "comes out" without reading the inverted tree is §4's rule about not stating
  what something does without opening it.
- **`deny.toml` named `num-derive` as one of the two syn-2 users**, so it needed
  correcting with this change. It was never only two: the syn 2/3 duplicate is
  still there, held by `clap_derive`, `tokio-macros` and `tracing-attributes`,
  and the skip entry stays.

Verified: the new test fails at opcode 3 against the old enum and passes against
the new one; `cargo test --workspace` is 631/1/1/93/3 (the lib count is +1 for
the new test); clippy and fmt clean; `cargo deny check` reports advisories,
bans, licenses and sources ok. **All fourteen allocation counts unchanged** —
3, 4, 3, 2, 1, 0, 2, 7, 208, 922, 24, 19, 0, 22 before and after.

#### 13b. Delete the name-normalization trap, then converge the copies — **done**

**Do this before 13e, not as part of it.** There are **nine** places that fold a
domain name into a comparable form in this codebase — counted, not estimated,
and the list below is all of them. Typing nine copies produces nine typed copies.
Delete the duplicates first.

- **`utils::normalize_domain_name` is a loaded gun in the public API.** It is
  `name.to_lowercase().trim_end_matches('.')` — the Unicode fold that
  `utils::ascii_lowered`'s own doc comment spends a paragraph forbidding, and
  that §8 names: `str::to_lowercase` folds U+212A KELVIN SIGN into `k`, so two
  names that differ on the wire come out equal and any table keyed on the result
  merges them. It has **no callers** outside its own tests, and it is the
  obviously-named function a new module would reach for.
  Delete it and `normalize_domain_name_for_comparison` with it.
- **`resolver::normalize` (1761) and `special_names::normalize` (178) are the
  same function**, written twice, in the shape §7 is entirely about. Both
  lowercase and append a trailing dot; both allocate unconditionally.
- **`special_names::in_zone` (174) is a fourth copy of `utils::is_at_or_under`**,
  and it allocates a `format!("{}.{zone}")` per call where the shared one
  compares bytes and allocates nothing. It gets the label-boundary rule right,
  which is the only reason this is a cleanup and not a finding.
- **`resolver::names_equal` allocates two `String`s per comparison**, via two
  `normalize` calls, and it is called inside `.any()` loops over the answer
  section (`resolver.rs:938`, and again through `label_count`). This is the one
  place in the section where the type work is expected to *reduce* the
  allocation count rather than hold it — record the before and after.
- The inline foldings in `cache.rs:{92,169}`, `ixfr.rs:{298,396}`, `xfr.rs:522`,
  `rfc5011.rs:{250,280}` and `dnssec_denial.rs:{310,311,366}` each answer a
  slightly different question (some absolutize, some do not). Converge them onto
  `utils` **only where they are asking the same question** — a difference that
  turns out to be real is a second function with a name that says so, not a
  parameter.

Verification: `zone::lookup_key`'s borrowing behaviour must not regress, since
the allocation test measures it directly (the three-lookups-per-query
measurement, `allocations.rs:269`).

**Done**, and the count above was low. What landed, and what the plan had not
seen:

- **`utils` gained three functions and lost two.** `names_equal` (allocation-free
  comparison), `absolute_lowered` (the `Cow` form of the shared `normalize`) and
  `label_count` (which never needed to normalize at all) replace
  `normalize_domain_name` and `normalize_domain_name_for_comparison`, the
  `to_lowercase` pair §8 forbids.
- **Nine was not the number.** The list counted the *folds* and missed two more
  implementations entirely: **`xfr::in_bailiwick`**, a sixth copy of "is this
  name at or under that one" — down-casing both sides into fresh `String`s — and
  **`ixfr::key`**, a seventh hand-written `absolute_lowered`. Both were found by
  reading the remaining sites rather than trusting the list, which is the only
  reason they are in this commit.
- **Folding `xfr::in_bailiwick` in was a small behaviour fix, not only a
  cleanup.** It required the two names to agree about the trailing dot —
  `strip_suffix` on an absolute name with a relative zone simply failed —
  where `is_at_or_under` treats the dot as optional on either side.
- **Four sites were deliberately left alone**, because they are not copies of
  this rule: `cache` already calls `ascii_lowered`; `rfc5011` and
  `ixfr::record_key` call `str::to_ascii_lowercase`, which *is* the RFC 4343
  fold and is not the trap (the trap is `to_lowercase`); and `dnssec_denial`'s
  is DNSSEC **canonical form** (RFC 4034 §6.1), a different rule that happens to
  coincide. A difference that turns out to be real is a second function, not a
  parameter — the plan said so and it applied to more sites than expected.
- **Two tests were deleted, not added.** Once `is_subdomain` and `in_bailiwick`
  became `utils::is_at_or_under`, `resolver::test_bailiwick_helpers` and
  `xfr::test_bailiwick` were asserting things about another module's function
  that `utils` already asserts, down to the same `notexample.com.` case. Both
  modules keep the tests of what they *decide* with the answer
  (`test_out_of_bailiwick_referral_is_not_followed`,
  `test_out_of_bailiwick_records_are_refused`), which is the half that is theirs.
  The lib count is **629**: +3 new `utils` tests, -3 deleted trap tests, -2
  duplicates.

Two more numbers written here from memory and corrected by counting, which is
now a pattern worth naming rather than a coincidence: a comment claimed
`special_names` consults "nineteen" private reverse zones (it is **27**), and
another named a test `test_referral_must_be_in_bailiwick` that does not exist.
Both were caught before the commit, both by grepping the thing being described.

Measured: the fourteen existing allocation counts are **unchanged**, and
`allocations.rs` gained a fifteenth measurement that records the one thing this
stage was expected to improve — **comparing two names went 2 allocations to 0**.
The old shape is measured beside the new one rather than described, because an
assertion that zero is zero is not evidence that anything moved (§10).

#### 13c. `Qtype` and `Rtype` are different things and are both `u16` — **done**

§8 already says "A QTYPE is not an RTYPE and a QCLASS is not a CLASS", and
records what it cost: `record_type_code(&r.rdata) == qtype` matched nothing for
ANY, so a QTYPE=ANY question at a name with data came back as an empty NOERROR
plus the SOA — a NODATA for a name that has data, and none of the shapes
RFC 8482 §4 permits. That was fixed **in `zone::of_type`**. The comparison is
still writable everywhere else, and `rdnsr` writes it twice:

- **`resolver.rs:938`** — `rr.rdata.rtype == query.qtype` decides `got_type`,
  which decides whether to stop chasing a CNAME.
- **`resolver.rs:1502`** — the same comparison decides `holds_the_answer`, and
  the next line is `let negative = !holds_the_answer`, which sends the DNSSEC
  validator looking for a denial proof.

For QTYPE=ANY both are unconditionally false. **The reachability half is
settled: it is fully reachable.** `rdnsr/src/main.rs`, `rdns/src/resolver.rs`
and `rdns/src/validation.rs` contain **no mention of ANY or 255 at all** — the
QTYPE is never checked, never rejected and never special-cased anywhere on the
resolver's path, so `dig ANY example.com @rdnsr` reaches those two comparisons
directly. That upgrades 13c from prophylactic to a fix for something a client
can do today.

**The consequence half is a hypothesis and must be tested, not assumed.** The
chain to check is `holds_the_answer == false` → `negative = true` → the
validator looks for a denial proof in the authority section of an answer that is
not negative → no proof → the verdict is not Secure → under `--dnssec-validate`,
which fails closed, SERVFAIL for a query that had a perfectly good answer. Write
that test first and watch it fail, per §1; if the chain breaks somewhere in the
middle, the finding is smaller than it looks and the section says so.

Meanwhile the ANY rule itself exists in four places and disagrees in spelling:
`zone::of_type` (which also carries the RFC 4035 §3.1.1 exclusion of RRSIG,
NSEC and NSEC3), `dnssec_answer.rs:81` and `:86`, and `nsec_cache.rs:48`, which
writes it as `qtype != 255`.

```rust
#[repr(transparent)] pub struct Rtype(u16);   // a type a record has
#[repr(transparent)] pub struct Qtype(u16);   // a type a question asks for

impl Qtype {
    /// The only comparison of a question's type against stored data.
    /// ANY is QTYPE 255 and no RR *is* that type (RFC 1035 §3.2.3); the three
    /// DNSSEC meta types stay out of an ANY answer (RFC 4035 §3.1.1).
    pub fn matches(self, rtype: Rtype) -> bool { … }
}
```

`Rtype` converts into `Qtype` — every RTYPE is a legal QTYPE. The reverse
conversion does not exist, which is what makes `rr.rdata.rtype == query.qtype`
stop compiling in all four places at once. AXFR (252), IXFR (251) and ANY (255)
become `Qtype` constants with no `Rtype` counterpart, which is the same statement
`utils::record_types`' comments already make in prose.

Cost: none — `repr(transparent)` `Copy` newtypes over `u16`, identical codegen.
Churn is the wide part: `qtype` appears ~180 times (52 in `resolver.rs`, 35 in
`rdnsd`) and `rtype` ~280 (45 each in `zone_signer.rs` and `update.rs`). Almost
all of it is mechanical, and the compiler drives it.

**Split into two commits, and `Qtype` is the first.** ~520 sites across both
newtypes is not one reviewable diff, and `Qtype` alone is what makes the bad
comparison stop compiling — `rr.rdata.rtype == query.qtype` is `u16 == Qtype`
whichever side is newtyped first. `Rtype` follows and tightens
`Qtype::matches(u16)` to `Qtype::matches(Rtype)`. Same forced-order reasoning as
13d's three.

**The finding was confirmed before anything was newtyped, and it held.** The
test 13c asked for — the same signed A RRset that
`test_signed_hierarchy_validates_as_secure` calls Secure, asked for with
QTYPE=ANY instead of A — failed against the old code with:

```
Bogus("www.example.test. was denied without an NSEC or NSEC3 proof")
```

A signed answer that verifies, reported as an unproven denial, which under
`--dnssec-validate` is a SERVFAIL for a good answer. The hypothesized chain was
right end to end: `holds_the_answer` false → `negative` true → the authority
section is searched for a proof a positive answer has no reason to carry. It now
passes.

**Three methods, because there are three different questions**, and collapsing
them is how the bug happened:

- `Qtype::matches(rtype)` — does this question select this stored record. The
  only cross-space comparison, and the only place ANY's meaning lives.
- `Qtype::is(rtype)` — is the question for exactly this type. Said out loud at
  the sites that mean it (`qtype.is(rt::DS)`, `qtype.is(rt::CNAME)`), so they do
  not read like a `matches` that forgot about ANY.
- `Qtype::of(rtype)` — `const`, so `utils::record_types` stays the one registry
  of numbers rather than growing a `Qtype` twin that can drift.

**`zone::of_type` lost its copy of the rule** — it was the place the ANY case
was got *right*, and its twenty-line doc comment explaining ANY and the three
DNSSEC meta types now lives on `Qtype::matches` with a pointer left behind. Two
tellings of one rule is where 13c started.

**The mechanical half was driven by rustc's own JSON spans, after regexes
over-matched six times.** Wrapping "the last argument that looks like a type
constant" turned `Some(7)` (a *serial*), `Some(2)` (a zone-list *length*),
`Some(1)` (a delta-chain length), `Some(11)` (another serial) and two NSEC3
fixture `u8`s into `Qtype`s. The compiler would have rejected all six — they are
`Option<u32>` and `u8` — but that is luck rather than method: a regex that
rewrites by shape can just as easily produce an edit that type-checks and is
wrong. The rewrite was redone from `cargo build --message-format json`, taking
the exact span rustc labels `expected \`Qtype\``, which cannot touch anything
the compiler did not point at. 87 of the ~200 sites went that way; the six
over-matches were reverted after auditing every `Some(Qtype::of(` in the tree.

Measured: **all fifteen allocation counts unchanged.** `cargo test --workspace`
630/1/1/93/3 (+1 for the ANY test), clippy and fmt clean, `cargo deny check` ok.

**`Rtype` landed too, and the first thing it found was a hole in `Qtype`.**
`dnssec_answer::answer_signatures` held a **fifth** copy of the ANY rule —
`if qtype != rt::ANY && sig.type_covered != qtype` plus a meta-type exclusion —
and it survived 13c-i intact, because that function still took a `u16` and its
callers were changed to pass `qtype.to_u16()`. **A newtype stops paying the
moment a signature is widened back to let it through**, and passing `.to_u16()`
is exactly how that happens without anyone deciding to. It is now
`qtype.matches(sig.type_covered)`, and `Qtype::matches` takes an `Rtype`, so the
widening is no longer available.

What else `Rtype` bought, beyond the comparison:

- **`Rtype::is_meta`** replaces `rtype == rt::ANY || rtype == rt::AXFR ||
  rtype == rt::IXFR` in RFC 2136 §3.4.1's prescan. The question there is not "is
  this ANY" but "could this value ever be a stored record", and now it says so.
  The meta-types stay representable as `Rtype`, because they genuinely arrive in
  a TYPE field — RFC 2136 §2.4 and §2.5 put TYPE=ANY in an UPDATE's prerequisite
  and update sections — with `_CODE` twins so `Qtype`'s constants stay `const`
  without a second registry of numbers.
- **The magic numbers had to be named.** `ParsedRecord::decode` matched on `1`,
  `2`, `5`, `6`, …, `encode` returned them, and `NameCompressor::write_rdata`
  matched `2 | 5 | 12`. None of those compile against a newtype, so they are
  `rt::A`, `rt::NS`, `rt::CNAME` now. That is the readability win a type forces
  and a lint would only have suggested.

**Two more failure modes of the span-driven rewrite**, both caught by the
compiler and both worth knowing before 13d does the same thing:

- **Struct-literal field shorthand.** rustc's primary span for `Foo { rtype, .. }`
  is the *field name*, so wrapping it produces `Foo { Rtype::new(rtype), .. }` —
  a syntax error, three times. The script now skips a span whose text is a bare
  identifier alone on its line.
- **Match patterns.** `fn` calls are not allowed there, so wrapping a match arm
  is a hard error rather than a wrong-but-compiling edit. That one turned into
  the constant-naming improvement above.

And a third over-match by the blunt sweep that preceded it: `Vec<u16>` →
`Vec<Rtype>` caught a vector of **key tags**, which are `u16` and not types at
all. Same lesson as 13c-i's `Some(7)`: a rewrite by shape needs a diff audit,
and the compiler catching it is luck rather than method.

Measured again: **all fifteen counts unchanged**, `cargo test --workspace`
630/1/1/93/3, clippy and fmt clean, `cargo deny check` ok.

**The other half of §8's sentence is missing from this section, and it belongs
here: "a QCLASS is not a CLASS."** The question carries `QueryClass`, a real
enum with `Any` and `None` variants that no stored record can hold; a record
carries `class: u16`. §8 records what that asymmetry already cost — a CH
question answered out of the IN zone, `CLASS=CH` echoed beside `CLASS=IN`
records. That was fixed in `rdnsd`'s query loop and in the zone parser, not in
the types, so it is the same shape as the ANY bug above and it is still
writable.

**A `Class` newtype cannot be done before 13d, which is why it is filed here
rather than done here.** `Edns::to_record` stores the requestor's UDP payload
size in `ResourceRecord::class` — the OPT pseudo-record repurposes CLASS exactly
as it repurposes TTL. So `class` has the same two-meanings-in-one-field problem
as `ttl`, it has the same cause, and it is fixed by the same change. **Do the
class newtype as the third commit of 13d**, alongside `Ttl`, once OPT no longer
lives in `additionals`. Doing it earlier means special-casing rtype 41, which is
the conditional invariant this whole section exists to stop writing.

#### 13d. `Ttl`, and lifting OPT out of the additional section — the deep one, **done**

**Two changes, and they are one change**, because the reason the TTL cannot
simply be clamped at the parse boundary is that the OPT pseudo-record's "TTL" is
not a TTL.

**The TTL half.** §2 records the `-1 as u64 == u64::MAX` bug — a negative TTL
picked by `min` as the smallest and pinning a cache entry for the life of the
process — and draws the rule: "Bounds and clamps belong at the boundary, once."
The clamp is currently at every use instead: **fourteen `ttl.max(0) as …` sites**
(`cache.rs:149`, `negative_cache.rs:149`, `nsec_cache.rs:{220,248,276,387,417}`,
`resolver.rs:{1234,1268,1272,1708}`, `zone_signer.rs:808`, and two in
`dnssec_test_util.rs`), plus **five `.min(i32::MAX as u32) as i32`** going back
the other way (`dnssec_answer.rs:290`, `negative_cache.rs:242`,
`nsec_cache.rs:835`, `zone_signer.rs:319`, `rdnsd/main.rs:863`). Every one is
correct. The invariant is that the fifteenth will be — and §2's own account of
this bug is that "a check that existed four times over was still missing where
it mattered".

`Ttl(u32)`, constructed only by `Ttl::from_wire(i32)` doing `.max(0)` — which is
RFC 2181 §8's instruction in as many words: a TTL with the top bit set should be
treated "as if the entire value received was zero". `ResourceRecord::ttl` becomes
private behind `rr.ttl()`, so the widening cannot be written by hand.

**The OPT half, and why it is the same change.** `Edns::to_record` writes
`ttl: self.flags() as i32` and `EdnsHeader::from_record` reads `rr.ttl as u32`:
in an OPT record that field is the extended RCODE, the EDNS version and the DO
bit. A blanket clamp at the parse boundary would corrupt it. One field carrying
two meanings depending on a sibling field *is* the conflation, and the fix is to
stop storing a pseudo-record in a resource-record list.

```rust
pub struct DnsMessage {
    …
    /// The OPT record, if the message carries one. Not in `additionals`,
    /// because OPT is not a resource record: RFC 6891 §6.1.1.
    pub edns: Option<Edns>,
}
```

What that buys, in order of how much it is worth:

- **A malformed state stops being representable, and it is one nothing rejects
  today.** RFC 6891 §6.1.1: "If a query message with more than one OPT RR is
  received, a FORMERR (RCODE=1) MUST be returned." Nothing in `validation.rs` or
  `lib.rs` checks this. Today the first OPT is read and *both* are re-serialized.
  `Option<Edns>` makes two impossible, and the parse gets the FORMERR the RFC
  asks for.
- **Eight linear scans of `additionals` per message become field accesses.**
  `lib.rs` searches the section for `rtype == OPT_RECORD_TYPE` at 1154, 1205,
  1281, 1294, 1307, 1319, 1329 and 1392 — `try_from_bytes` for the extended
  RCODE, `to_bytes`, `edns`, `edns_header`, `has_edns`, `udp_payload_size`,
  `set_edns`'s `retain`, and the truncation path's `retain`. (Line 1249 is a
  ninth comparison but not a scan: it is the per-record branch inside the write
  loop that stamps the extended RCODE into the OPT TTL, and it becomes
  unnecessary rather than cheaper. Counting it as a scan would overstate the
  win, and the two `OPT_RECORD_TYPE` hits above line 1462 in that file are in
  `mod tests`.)
- **The OPT exemption disappears from filters that must remember it.**
  `rdnsr/main.rs:1156` is `additionals.retain(|rr| rr.rdata.rtype ==
  OPT_RECORD_TYPE || keep(rr))` — a filter over the additional section that has
  to spare OPT by hand. That clause is the bug waiting to be omitted from the
  next such filter; with a field there is nothing to spare.
- **`to_bytes_within_buf`'s truncation path cannot drop the OPT record.** It
  currently keeps it with a `retain`, and the size limit is signalled *via* EDNS,
  so losing it there would be losing the thing that says why.

**The one decision this must get right: a malformed option list must stay
FORMERR-with-a-reply, not silence.** `rdnsd` answers a bad option list with
FORMERR today (`main.rs:478-486`), and it can only do that because the message
parsed — `DnsMessage::try_from_bytes` failing means `main.rs:1465` and `:2072`
`return` **with no reply at all**, and `error_bytes` takes a parsed
`&DnsMessage`, so there is nothing to build a FORMERR from. Making the option
list a hard parse error would turn a diagnosable FORMERR into a client timeout.
So `Edns` keeps the option list unparsed and the fallibility at the accessor:

```rust
pub struct Edns {
    /// CLASS and TTL: payload size, version, DO. Infallible — a parsed record
    /// always has both fields, so nothing here can be malformed.
    pub header: EdnsHeader,
    /// The option list as it arrived. Parsed on demand, because the answer path
    /// reads three flags and never looks at an option.
    rdata: Box<[u8]>,
}
impl Edns {
    pub fn options(&self) -> Result<Vec<EdnsOption>, WireError>;
    pub fn check_options(&self) -> Result<(), WireError>;  // the walk, no build
    pub fn option(&self, code: u16) -> Result<Option<&[u8]>, WireError>;
}
```

That is the distinction `EdnsHeader` already found and wrote down — "Infallible,
and that is the difference between this and the option list" — made structural.
It also preserves the allocation profile by construction: the option `Vec` is
built only when something asks for the options, which is what `edns_header()`
exists to avoid and what the `query_bytes_with_edns` measurement in
`allocations.rs:146` is watching.

**What has to be got right in the serializer**, each of which wants its own test:

- **ARCOUNT is `additionals.len() + edns.is_some() as usize`.** It is currently
  `additionals.len()`, and this is the arithmetic most likely to be wrong.
- **OPT is written after the other additionals**, so that `tsig::append_tsig` —
  which appends to the serialized bytes and bumps ARCOUNT itself (`tsig.rs:859`)
  — still leaves the TSIG last, as RFC 8945 §5.1 requires.

  **That is true, but not for the reason it first appears, and the real reason is
  fragile enough to write down.** Writing OPT last within the struct's own
  section would put it *after* a TSIG if a TSIG were ever in `additionals` when
  the message was serialized. It never is: `TSIG_TYPE` appears nowhere outside
  `tsig.rs`, that module works entirely on raw packet bytes (`strip_tsig`,
  `append_tsig`), and the only place a TSIG record sits in a parsed
  `additionals` is a test at `tsig.rs:1143` asserting the appended bytes parse
  back. `make_response` and `error_bytes` both build `additionals: Vec::new()`,
  so no reply ever inherits a request's TSIG. The ordering invariant therefore
  holds by *where TSIG lives*, not by anything the serializer enforces — and
  `no_input_panics.rs` mutates and re-serializes messages, so a fuzz case can
  construct the OPT-after-TSIG ordering that production cannot. Add an assertion
  that a message carrying both serializes with TSIG last, so the next person to
  put a TSIG in a struct finds out from a test rather than from dnspython
  reporting a malformed record.
- **The extended RCODE still splits across the header and the OPT TTL** at
  serialization time and is reassembled at parse time. The current design note
  is right and stays: the 12-bit RCODE is a property of the *message*, so it
  lives in `DnsMessage::rcode` and nowhere else.
- **An OPT record in the answer or authority section stays an ordinary record.**
  Only the additional section's OPT is lifted, because only there does it mean
  anything.
- `dnssec_chain::group_rrsets` (`:751`) skips OPT; after this it is skipping
  something that can no longer be in the sections it is given. Delete the clause
  rather than leaving a guard against an impossible state.

Churn is the largest in the section: **65 `DnsMessage { … }` literals** across
five crates (most in tests) each gain a field, and **109 call sites** touch
`set_edns` / `edns()` / `edns_header` / `has_edns` / `udp_payload_size`. Most of
the 109 get simpler. The 65 are mechanical and the compiler names every one.

**The OPT commit is done.** `DnsMessage.edns: Option<Edns>`, and everything the
plan asked for held:

- **The malformed state is refused.** `more_than_one_opt_record_is_formerr`
  drives two OPT records off the wire and requires FORMERR (RFC 6891 §6.1.1).
  It fails against the old code by construction, because the old code had no
  check at all — the first was read and both were re-serialized.
- **ARCOUNT is one expression**, `additionals.len() + usize::from(edns.is_some())`,
  and `arcount_counts_the_opt_record_that_is_not_in_the_section` is the guard.
- **TSIG stays last**, and the test says why that is worth asserting rather than
  assuming: the invariant holds because `TSIG_TYPE` appears nowhere outside
  `tsig.rs` and no reply carries a TSIG *through* `to_bytes`, not because the
  serializer enforces it. `a_signed_message_with_edns_still_ends_in_its_tsig`
  checks it functionally — `strip_tsig` needs the TSIG last, so if OPT landed
  after it the signature would not verify.
- **The option list stayed lazy**, which is what preserves the FORMERR reply.
  `Edns` holds `rdata: Box<[u8]>`; `check_options` is the FORMERR question and
  `options()` is the parse.

**Two tests changed, and both changes are the point rather than collateral.**
`test_edns_set_and_read` asserted that the additional section held *exactly one*
OPT record after `set_edns` — a real hazard when `set_edns` pushed onto a `Vec`
and had to `retain` the old one away, and a meaningless thing to count once the
field is an `Option`. `test_malformed_edns_options_surface_error` called
`msg.edns()` and expected `Err`; reaching the OPT record is infallible now and
`check_options` is where it fails. Each kept its subject and moved to the
question that still exists (`CLAUDE.md` §1: a test that has to change is a test
that encoded the old shape — say so).

**One allocation measurement moved, and the number did not.** "the same three
fields through the full option parse" used to call `edns()`, which parsed the
option list on the way to the record and so read 2. `edns()` allocates nothing
now, so the measurement calls `options()` — the same two allocations, charged to
the call that actually wants them. A sixteenth measurement, "reach the OPT
record", records the 0 that replaced it. Every other count is unchanged.

`cargo test --workspace` 633/1/1/93/3 (+3 for the new tests), clippy and fmt
clean, `cargo deny check` ok.

**`Ttl` landed, and the forced order earned its keep.** `Ttl(u32)` with
`Ttl::from_wire` clamping per RFC 2181 §8, applied once where the bytes are
read. The fourteen `ttl.max(0) as …` sites and the five
`.min(i32::MAX as u32) as i32` conversions are gone; `ResourceRecord::ttl` and
`ZoneRecord::ttl` are `Ttl`, and a negative one can no longer be built.

**The OPT hazard the plan predicted was real, and bit at exactly the predicted
place.** With `ResourceRecord::ttl` clamped at parse, an OPT record's TTL —
which is not a TTL but the extended RCODE, the EDNS version and the DO bit
(RFC 6891 §6.1.3) — would have been erased whenever the extended RCODE's high
byte had its top bit set. Moving OPT into a field in the previous commit was
*necessary but not sufficient*: the OPT record was still being parsed **as a
`ResourceRecord`** and taken apart afterwards, so it still went through `Ttl`.

The fix is the honest one rather than a special case: the additional section is
read through an `Additional::{Record, Opt}` enum, and an OPT is decoded straight
from its wire fields — never becoming a `ResourceRecord` at all. `Edns::from_record`
and `EdnsHeader::from_record` are deleted; there is no record to read from. This
is the shape the section keeps arriving at: the conditional invariant ("clamp
unless it is rtype 41") is the thing to avoid, and the way to avoid it is to stop
pretending the pseudo-record is a record.

Nothing sends an extended RCODE ≥ 2048 today, and that is not a reason to build a
parser that cannot represent one.

**A boundary test, and one regression test kept its meaning.**
`a_ttl_with_the_high_bit_set_parses_as_zero` drives `-1`, `i32::MIN` and `-3600`
*off the wire* rather than through `Ttl::from_wire`, because the claim being
tested is that parsing a record applies the rule — which is what lets fourteen
call sites stop applying it. `cache`'s `a_negative_ttl_does_not_pin_an_entry_forever`
still drives the same three values and still passes; its subject moved from "the
cache clamps" to "the cache no longer has to", and the comment above the cache's
`min_ttl` says so.

`cargo test --workspace` 634/1/1/93/3, clippy and fmt clean, `cargo deny check`
ok, **all sixteen allocation counts unchanged**.

**`Class` landed, and 13d is done.** `Class(u16)` with `IN`/`CH`/`HS`, on
`ResourceRecord::class` and `ZoneRecord::class`. The same one-way conversion the
other two pairs have — `From<Class> for QueryClass`, no way back — and
`QueryClass::matches`/`is` to go with `Qtype`'s.

Two things it turned up that the plan had not written down:

- **RFC 2136 repurposes a record's CLASS field**, so `update.rs` reads one as a
  QCLASS on purpose: §2.4 and §2.5 put ANY (255) and NONE (254) there to say what
  to *do* with the record. That is what `From<Class> for QueryClass` is for, and
  `Class::is_meta` names the two values no stored record can be in. The plan had
  described the conversion as a formality; it is load-bearing on the UPDATE path.
- **`Class` needs a `Default`, and it is not `derive`d.** `DelegationEvidence`
  derives `Default`, and a derived `Class` would be `CLASS0` — not a class at
  all. It is `IN`, with a comment saying why that is the honest default here: the
  zone parser refuses every other class, so a record built without saying its
  class is in the only one there is.

One test message changed and no test did: `zone_writer`'s "unknown class 42" now
reads the numeric value rather than `Display`, which renders the RFC 3597 §5
generic form `CLASS42` and would have made the message say "unknown class
CLASS42".

`cargo test --workspace` 634/1/1/93/3, clippy and fmt clean, `cargo deny check`
ok, **all sixteen allocation counts unchanged**. That is three commits in the
forced order the section predicted, and each of the two newtypes was only
correct because the one before it had landed.

#### 13e. `Name` and `NameKey` — the pipeline that ends in `String` (**partly done**)

`dname.rs` states the intent already: "The design is you can only go
`bytes -> DName -> unpacker -> UnpackedDName -> String`. This way the type system
makes sure you don't end up with dname fragments." It is right, and then the
pipeline terminates in `String`, which carries no evidence of any of it.

Four invariants are live in this codebase and none is in a type: **absolute or
relative** (`zone::absolutize` resolves it, `utils::normalize_domain_name` used
to strip it), **ASCII case-folded or not** (required of anything used as a map
key, and `cache` got it wrong once), **≤255 octets** (checked by
`RequestValidator` on the way in — and `rdnsr` runs no validator at all, per §2 —
and *not* checked by `dname_to_bytes`, which validates label length and total
length never), and **non-empty labels of ≤63 octets** (checked at
`write_label`, i.e. at serialization, which is the last possible moment).

**The escape question is settled, and the answer is that both of our functions
are half of a design and neither is the whole of one.** Researched 2026-08-02;
what follows replaces the open question the section was drafted with.

**What the RFCs say.** Backslash escapes are defined only in RFC 1035 **§5.1**,
which is the *master file* format: "`\X` where X is any character other than a
digit (0-9), is used to quote that character so that its special meaning does not
apply. For example, `\.` can be used to place a dot character in a label."
§3.1 defines the wire form with no escapes at all — "each label is represented as
a one octet length field followed by that number of octets" — and says a label
may hold anything: "although labels can contain any 8 bit values in octets that
make up a label…". So an escape is a *presentation* device, and `.` inside a
label is an ordinary octet on the wire. A representation that stores presentation
text and then treats `.` as a separator is conflating the two.

**What everyone else does**, checked rather than assumed:

| implementation | stores | evidence |
|---|---|---|
| PowerDNS `DNSName` | wire | "accept escaped ascii presentations of DNS names and store them **'natively'**"; `string_t d_storage`, chosen to allow "non-printable characters" in labels |
| hickory-dns `Name` | decoded labels | `Name::from_ascii("email\.name.example.com.")` is documented as **equal to** `Name::from_labels(["email.name", …])` — one label containing a dot |
| dnspython `dns.name.Name` | decoded labels | `labels` is "a tuple of `bytes` in DNS wire format specifying the DNS labels" |
| miekg/dns (Go) | **presentation strings** | "Resource records are native types. They are not stored in wire format" — the counter-example |

Three of four resolve escapes at the presentation boundary and store decoded
content. The fourth keeps presentation strings — **and still never splits on
`'.'`**: it ships `NextLabel`, `PrevLabel`, `Split`, `SplitDomainName`,
`CountLabel` and `IsDomainName` precisely because a naive split is wrong. This
codebase picked presentation storage *and* the naive split, which is neither
design.

**Two live defects follow, and both were provoked rather than reasoned about:**

- **A zone file mis-encodes an escaped dot.** `a\.b IN A 192.0.2.1` should be
  one label `a.b` (`03 61 2e 62`). It becomes **two** labels, `a\` and `b`
  (`02 61 5c | 01 62`): the tokenizer keeps the backslash (`zone.rs:885` says
  names are not its business), nothing ever resolves it, and `dname_to_bytes`
  splits on the dot. It round-trips through our own parser unchanged, which is
  §1's warning about a parser agreeing with its own serializer.
- **Two distinct wire names collapse to one string.** The one-label name
  `[03 'a' '.' 'b']` and the two-label name `[01 'a' 01 'b']` both read as
  `"a.b."`. That breaks the injectivity every name-keyed map and every
  tree-shaped question assumes: `is_at_or_under("evil.com.", "com.")` answers
  **true** for a single-label name that is a *sibling* of `com.`, not a child.
  This arrives off the wire, so it is reachable by a remote party. **No
  end-to-end exploit has been demonstrated and this should not be described as
  one** — what is demonstrated is that the representation is not injective and
  that a bailiwick answer derived from it can be wrong about the tree.

**Which leaves three options for 13e**, and the sketch below assumes the first:

1. **Store decoded labels** — `Name(Vec<Label>)` or wire form, escapes resolved
   at the zone parser and re-escaped by the writer. What PowerDNS, hickory and
   dnspython do. Fixes both defects. The largest change in §13 by some way, and
   it is not `Name(String)`: a decoded label containing a literal dot cannot be
   joined into a `String` without becoming ambiguous again, which is the flaw in
   this section's original sketch.
2. **Keep presentation strings and make every operation escape-aware** — the Go
   design. `dname_to_bytes`, `label_count`, `is_at_or_under`, `absolute_lowered`
   and the zone index all need escape-aware label walks. Fixes both defects,
   spreads the rule across every name operation rather than concentrating it,
   and is the design that library ships helpers for because it is easy to get
   wrong.
3. **Refuse what cannot be represented** — reject an escape in an owner name at
   the zone parser, and reject a `.` inside a label coming off the wire. The
   codebase is already half-committed to this: `zone_writer::writable_name`
   refuses any name containing `\`, so such a zone cannot be written out today.
   Cheapest by far, makes the invariant true rather than merely documented, and
   costs the ability to serve a legal-but-vanishingly-rare name.

**Recommendation: 3, then reassess.** It closes both defects in an afternoon,
makes `Name`'s invariant honest (a name has no dots inside labels, so `.` *is*
the separator), and leaves 1 available later without having built anything that
has to be undone. It is also the only one of the three that can be verified by a
test that fails today. What it must not be is silent: refusing input is a
behaviour change and belongs in the release notes, not just in a type.

**Option 3 is done.** Both defects are closed, at the two boundaries where a name
enters or leaves as a `String`:

- **`dname::unrepresentable_octet`** names the two octets that have no faithful
  spelling in presentation text — `.`, the separator, and `\`, the escape — and
  is checked in `UnpackedDName`'s `TryInto<String>` (wire → `String`) and in
  `write_label` (`String` → wire). A refused name is `WireError::Unsupported`,
  which reads as **NOTIMP rather than FORMERR**: the sender is not at fault, this
  is a legal encoding we decline to represent, and it is the same judgement
  `Label::try_from_bytes` already makes about binary labels.
- **The zone parser refuses an escape in an owner name**, so a zone carrying one
  fails to *load* rather than failing the first query for it. A name-valued RDATA
  field is caught by `write_label` at `RecordData::from_parsed`, which is still
  parse time.

The invariant this buys is the one 13e's `Name` needs and could not previously
state: **a stored name contains no dots inside labels and no escapes, so `.` is
the separator and `str::len()` is the wire length.** That was the blocker.

Verified: both wire tests and the zone test were watched failing first.
`cargo test --workspace` 637/1/1/93/3 (+3), clippy and fmt clean, sixteen
allocation counts unchanged, and **720,006 mutated cases through
`no_input_panics` with no panics** — worth the soak because this changes a
pre-authentication path (`TODO.md` #12).

**What it costs, stated plainly rather than buried:** a name with a dot or a
backslash inside a label is now refused instead of mangled. Such names are legal
(RFC 1035 §3.1) and vanishingly rare, `zone_writer::writable_name` already
refused to emit one, and every alternative required changing how every name in
the codebase is stored. This is a behaviour change and belongs in release notes.

**13e is no longer blocked**, and the remaining question is narrower than it was:
with the invariant true, `Name(String)`/`NameKeyBuf` is sound — the objection was
never the newtype, it was that the newtype would have been asserting something
false.

**The original open question, kept because it is why the section nearly shipped
a `Name(String)` that could not work:** A name in this codebase
may be in *presentation* form, and presentation form has escapes: `zone.rs:885`
says so in as many words — "a bare token like `a\.b` is a name whose meaning
changes if the backslash is dropped, and names are not this function's business"
— and `zone_writer::record_to_string` refuses an owner name "it needs escapes
this parser does not read back". Meanwhile `dname_to_bytes` splits on `'.'` with
no escape handling at all, so `a\.b.example.com.` becomes the labels `a\`, `b`,
`example`, `com`. Two functions in the same crate disagree about what a `String`
holding a name means.

That has three consequences for this stage, and the first one is fatal to the
draft as written:

- **`≤255 octets` cannot be checked with `s.len()`.** The limit is on wire
  octets; presentation length is not wire length as soon as one escape is
  present. Either `Name` holds a form where the two coincide, or the invariant
  has to be stated over a conversion rather than over the string.
- **A newtype that does not settle this just renames the ambiguity**, which is
  the shallow pass this section exists to avoid.
- Whether an owner name needing escapes is even *reachable* — can the zone
  parser produce one, can one arrive off the wire — is an open question worth
  answering first, because "unreachable" makes this a five-line assertion and
  "reachable" makes it a design decision.

**And the sketch's key type was wrong.** `NameKey<'a>(Cow<'a, str>)` cannot be
what `Zone::index` is keyed by: a map key must be owned, and a lifetime
parameter would infect `Zone`, `DnsCache` and everything holding one. The shape
that works is the one `std` already uses for exactly this problem — a borrowed
unsized type plus an owned counterpart, `str`/`String` and `Path`/`PathBuf`:

```rust
/// The only form a name may be a map key or a comparison operand in:
/// absolute, ASCII case-folded (RFC 4343). Borrowed, unsized, like `str`.
#[repr(transparent)] pub struct NameKey(str);
/// Its owned counterpart. `Borrow<NameKey>` is what lets
/// `HashMap<NameKeyBuf, _>::get(&NameKey)` look up without allocating.
pub struct NameKeyBuf(String);

/// A name as written or as it arrived. Case preserved — 0x20 encoding and
/// zone-file presentation both depend on it.
pub struct Name(String);
```

`HashMap<NameKeyBuf, _>` instead of `HashMap<String, _>` makes `cache.rs`'s
original bug — keying on a name nobody folded — not compile, and the
`Borrow<NameKey>` impl is what keeps the lookup allocation-free. There is one
constructor, so there is one place the RFC 4343 reasoning lives, which is the
whole of what 13b is clearing the ground for.

**On cost:** `Name(String)` and `NameKeyBuf(String)` have `String`'s layout and
allocation count. The borrowing lookup that `zone::lookup_key` performs today —
which returns `Cow::Borrowed` for every name that arrives absolute and lower
case, i.e. almost all of them — survives as a function returning
`Cow<'a, NameKey>`, so the DHAT win it was introduced for (four allocations per
query, ~14% of the answer path) is preserved by construction. The expected net
movement is downward, from 13b's `names_equal`.

**This is the stage most likely to be abandoned**, and that is an acceptable
outcome rather than a failure: if the escape question turns out to need its own
decision, stop after 13d and file the rest. Four fifths of this section's value
is in 13a-13d, none of which depends on 13e.

**Done: the map keys. Not done: `Name` on `ResourceRecord`/`QuerySection`.** Two
constraints found while building it changed what this stage can be, and both are
worth more than the code:

**1. The `str`/`String`-shaped pair needs `unsafe`, and this workspace has
none.** `NameKey(str)` unsized with `Borrow<NameKey>` — the `Path`/`PathBuf`
shape the plan sketched — cannot be constructed without transmuting `&str` to
`&NameKey`. `grep -rn unsafe` over all five crates returns **zero**, and a
newtype's ergonomics is not a good enough reason to introduce the first of it.
What landed instead is `NameKeyBuf(String)` with `Borrow<str>`: an *insertion*
cannot skip the fold, a *lookup* takes a `&str` the caller folded with
`absolute_lowered` (which borrows, so nothing allocates). That is the direction
the `cache` bug came from, so it is the half worth having — but it is half.

**2. A tuple key cannot borrow, so `(name, qtype)` maps keep `String`.**
`HashMap<(NameKeyBuf, Qtype), V>::get` has no way to accept a borrowed name:
`Borrow` cannot decompose a tuple, so every lookup would have to *build* a
`NameKeyBuf` and allocate — on `DnsCache::get`, which is on `rdnsr`'s query path.
`cache`, `negative_cache`'s NODATA map and `nsec_cache`'s wildcard map therefore
keep `(String, Qtype)`. The fix is a nested `HashMap<NameKeyBuf, HashMap<Qtype,
V>>`, which is a data-structure change with its own eviction consequences and is
not what this stage is for. **Filed, not forgotten.**

So the maps that are keyed by a name alone are typed — `Zone`'s `index` and
`non_terminals`, `negative_cache`'s NXDOMAIN map, `nsec_cache`'s zone proofs,
`resolver`'s delegation and key caches, `ixfr`'s delta log, `metrics`' zone
gauges — and the three tuple-keyed caches are not.

**The gate did its job, and this is the entry it exists for.** The first version
allocated twice per record in `Zone::add_record`: `lookup_key(…).into_owned()`
and then `NameKeyBuf::new` folding it a second time.
`tests/allocations.rs` read **208 → 215** on an eight-record zone and **922 →
949** on signing one, and refused to pass. The cause was fixed rather than the
number moved (§10): `NameKeyBuf::from_folded` takes a string already in key form,
for the one caller — `Zone`, whose key is absolutize-against-the-origin *then*
fold, which `NameKeyBuf::new` cannot express because it has no origin. Its
invariant is `debug_assert`ed, and checked *without allocating*, because the
allocation test runs in debug and a checking `absolute_lowered` would have shown
up as the very number it is there to hold.

**A review of the ten commits found one regression the gate could not see, and
that gap is now closed.** Nothing in `tests/allocations.rs` measured *parsing* an
EDNS-bearing query — the measurements around EDNS all worked on an
already-parsed message — which is exactly the path 13d's OPT commit changed. The
first `Additional::try_from_bytes` peeked at a record's TYPE by parsing the owner
name a second time, costing an extra `String` on every modern query. Measured
against `main` with the same probe: **7 before #13, 8 after that commit, 6 once
the fields are read once and branched on** — `read_record_parts`, which is also
the removal of a second copy of the field arithmetic (§7). The extra one below
`main` is the `RecordData` an OPT record no longer needs building on the way
past.

The measurement is now permanent, with that history next to it, because a number
that has moved three times is exactly the kind that gets argued about later.

**Left for later, deliberately:** `Name` on `ResourceRecord::name`,
`ZoneRecord::name`, `QuerySection::qname` and the name fields of `ParsedRecord`
— roughly 460 sites. Its value is lower than it was when this section was
drafted: 13b moved every fold and every comparison behind `utils`, and #13e's
option-3 commit made the invariant those functions assume actually true. A `Name`
that derefs to `str` would add little the constructors do not already give;
one that does not deref is the 460 sites. Worth doing when something else needs
to touch that surface anyway, not on its own.

#### Order, and why it is this order

1. **13a** — smallest, verified, fixes a live conformance bug, removes two
   dependencies. Good first commit because it settles whether the section is
   worth continuing.
2. **13b** — deletes six things and types none of them. Pure subtraction, and
   the prerequisite for 13e being one type rather than seven.
3. **13c** — mechanical, zero-cost, and the compiler finds the two `resolver.rs`
   sites rather than a reviewer having to.
4. **13d** — the deep one, in **three commits and the order is forced**: OPT out
   of `additionals` first, then `Ttl`, then `Class`. Both newtypes are only
   correct once OPT stops repurposing the fields they cover, and doing either
   first means special-casing rtype 41 — the conditional invariant this whole
   section exists to stop writing.
5. **13e** — largest churn, done when everything it would collide with is
   settled, and the one stage it is legitimate to abandon (see its last
   paragraph).

Each stage is its own commit with its own before/after allocation counts in the
message. A stage that cannot hold the counts stops the section rather than
lowering the bar — that is §10's rule, and the `bench_logger_throughput` floor is
what happens when it is not followed.

Estimate: **13a and 13b are an afternoon each.** 13c is a day of mechanical
edits. 13d is the bulk — call it four to five days across its three commits,
most of it in the 65 struct literals and the serializer tests. 13e is a further
two to three, *if* the escape question does not reopen it. Nothing in 13a-13d is
research; all of it is churn with a compiler holding the other end.

#### What an adversarial pass changed, and why the record is kept

This section was reviewed against the code and the registries the day it was
written, before anything landed. Five claims did not survive, and they are kept
here rather than silently patched because the pattern in *how* they failed is
the useful part (`CLAUDE.md` §11):

- **"15 is reserved rather than unassigned"** — asserted from memory. IANA says
  15 is *Unassigned*, and the fact worth having was one the draft missed
  entirely: **opcode 6 is DSO (RFC 8490), assigned**, and this codebase already
  carries `ResponseCode::DsoTypeNotImplemented` for it. The argument got
  stronger by being checked. Two of the three §1 sins in one sentence — citing
  from memory, and citing the thing that sounds right.
- **"seven normalizations"** — the prose said seven and the list under it had
  nine. A count nobody counted.
- **"reachability is not proven"** for the QTYPE=ANY comparisons — it was
  provable in one grep, and the answer was that ANY is *never mentioned* on
  `rdnsr`'s path. Hedging is not the same as checking, and it reads the same on
  the page.
- **`NameKey<'a>(Cow<'a, str>)`** — cannot be a map key; a lifetime would infect
  every struct holding one. The draft carried the *lookup* side of the problem
  and forgot the *storage* side, which is the half that made the type necessary.
- **The escape prerequisite in 13e** — missed entirely, and it is the one thing
  in the section that could invalidate a whole stage.

The through-line: every one of the five was a place the draft reasoned about
what the code *should* look like instead of opening it. Which is §4's rule
about never stating what a function does without reading it, applied to one's
own plan — a plan is a claim about the code too.

### 14. What #13 left on the table — three candidates, not a plan

Written 2026-08-02, from a pass over the code *after* #13 landed, asking what
the new types unlocked. **The pass found a live defect before it found any
candidates**, and that defect is the argument for the second item below.

**Fixed on the way, not filed:** `rdnsd` answered a response sent to its **UDP**
port. §8 of `CLAUDE.md` says to test QR "on both daemons", so both *transports*
of both daemons were checked rather than the rule taken as read. `fn answer`
(TCP) has made that test since the rule was written; `answer_datagram` (UDP)
never had it, and UDP is the transport it matters on — nothing makes the peer
prove its address first, so a spoofed datagram naming another server as its
source was a packet loop neither end could see. `rdnsr` has one `handle_query`
shared by both of its transports and so could not drift; `rdnsd` has two
answering paths and one of them was simply never given the check.

These three are **candidates, deliberately not a staged plan**. #13 was planned
in full before anything landed because it was five interlocking changes with a
forced order. These are independent, and any one of them is a self-contained
commit.

#### 14a. `Serial(u32)` — RFC 1982 serial arithmetic — **done 2026-08-02**

The cheapest, and the one with a second copy already in the tree.
`secondary::is_newer` implemented RFC 1982 §3.2 correctly and said why: "a serial
that wraps past 2^32 is still an increment, and a plain `>` would read it as a
rollback and leave the zone frozen for the rest of its life."
`notify.rs:124-127` then wrote the same wrapping comparison out inline, with its
own copy of the citation. That is `CLAUDE.md` §7's shape, in the one piece of
arithmetic in DNS most likely to be got wrong with a `>`.

A `Serial(u32)` that **deliberately does not implement `PartialOrd`** makes
`a > b` a compile error and leaves `a.is_newer_than(b)` as the only comparison.
Roughly fifteen sites: `ixfr`'s `from_serial`/`to_serial` and `chain_from`,
`notify`, `metrics::set_zone_serial`, `secondary`, `zone::serial`,
`xfr::soa_serial`, and `ParsedRecord::SOA`.

Not unlocked by #13 — it was always available. It is here because it is the same
class, the span-driven tooling from 13c/13d applies unchanged, and the second
copy is already written.

**Done.** Landed as planned. Both implementations of RFC 1982 §3.2 are gone and
`Serial::is_newer_than` is the one copy, with `secondary::is_newer`'s reasoning
moved onto the type. Fifteen was about right: the type reached
`ParsedRecord::SOA`, `Zone::serial`, `xfr` (`soa_serial`, `fetch_soa`, both
assemblers, `IxfrOutcome::UpToDate`), `ixfr` (`ZoneDelta`, `chain_from`,
`requested_serial`), `notify` (`changed_zones`, `zone_serials`,
`notified_serial`), `secondary::TransferState`, `zone_signer::signed_serial`,
`metrics` (`ZoneGauge`, `ZoneFacts`, `set_zone_serial`), and in `rdnsd` the
announcement tuples, `send_notify`, `announce_transfer` and `record_state`.

Four things worth keeping:

- **There was no live defect, and this says so rather than manufacturing a
  failing test.** `CLAUDE.md` §1 requires a regression test to be watched failing
  against the old behaviour; there is no such test here, because nothing in the
  tree compared two serials with an operator — grepped for, not assumed. The
  compile error is the guard, and it protects the sites nobody has written yet.
  §17's argument is what justifies the change without one.
- **`Display` had to forward the whole formatter**, not `write!(f, "{}", self.0)`
  — which is what [`Ttl`] next door does. `zone_writer` lays an SOA out as
  `{serial:<12}` and `rdnsctl status` as `{:>6}`, and the one-line impl ignores
  both silently: the zone file still parses, the column just stops lining up.
  There is a test for it, because the claim was about to go in a doc comment
  unchecked (§4).
- **One `>` on serials existed after all, in a test, and it was right.**
  `a_date_style_serial_still_moves` asserts `signed > date_style` to show that
  `signed_serial` *adds* the time term rather than `max`ing it — an arithmetical
  claim that `is_newer_than` cannot carry, since a wrapped serial satisfies that
  too. It is now `signed.to_u32() > date_style.to_u32()`, the only place in the
  tree that unwraps a `Serial` to compare one, with a comment saying why.
- **`FromStr`, because the presentation form is a decimal number in two places**
  — the zone file's SOA field and the secondary state file's second column —
  and both already read it with `.parse()`.

Verified: `cargo test --workspace` is 640/1/1/94/3, against 637/1/1/94/3 before
(one test left `secondary`, four arrived beside `Serial`); clippy with
`-D warnings` and `cargo fmt --all --check` clean. `cargo deny` was not re-run
and does not apply: no dependency moved.
**All eighteen allocation counts unchanged** — 3, 4, 3, 2, 1, 0, 6, 0, 2, 7, 208,
922, 24, 19, 0, 2, 0, 22 before and after. Criterion was **not** run and does not
need to be: §13's gate calls it the backstop for a change that trades an
allocation for time, and a `#[repr(transparent)]` newtype carrying the same `u32`
through the same arithmetic trades nothing. The allocation counts are the claim,
and they are exact.

#### 14b. QR as a type — **done 2026-08-02**

The defect above is the whole argument, so it needs no other one. Two answering
paths in `rdnsd`, one check, and the rule written down in `CLAUDE.md` §8 since
before either was last touched.

A `Request` newtype that can only be produced by a "parse a packet that arrived
at a listening socket" constructor makes the test impossible to omit rather than
something each path has to remember. The blast radius is the socket entry points
rather than all of `DnsMessage`: the resolver sends queries and reads responses,
`tsig` validates both directions, and `DnsMessage` has to stay usable for all of
that — so this is a wrapper at the door, not a split of the message type.

**Done.** `rdns::validation::Request` is that door, and all three socket entry
points go through it: `rdnsd`'s `answer` (TCP) and `answer_datagram` (UDP), and
`rdnsr`'s `handle_query`. It `Deref`s to `DnsMessage` for reading and
deliberately has **no `DerefMut`**, since `request.response = true` would put the
value back in the state the type exists to exclude.

Three things the plan did not say:

- **"Impossible to omit" was too strong, and the type's doc comment now says
  so.** `DnsMessage::try_from_bytes` is still public and still correct for the
  resolver, for `xfr`, and for a test, so a new answering path *could* call it
  and skip the check exactly as `answer_datagram` did. What actually changed is
  that there is one named door with the reason attached, that the drop decision
  is written once rather than once per path, and that the next path will be
  copied from something that checks. Real teeth would mean `make_response` and
  its siblings taking `&Request`, which is a bigger change than this scopes and
  would push every unit test of them through a serialize-and-reparse round trip.
  Overclaiming it in the doc comment would have been §4's mistake exactly.
- **It needed a seventh error type**, `error::RequestError`, with two variants —
  and the second is why: a caller branches on them. `Wire` is garbage or a parser
  probe; `NotAQuestion` is a traffic loop or a spoofed source, and `rdnsd` logs
  them differently because an operator chasing one needs to tell them apart.
  A QR=1 packet is emphatically *not* a `WireError`: it decoded perfectly, and
  none of that type's four variants is the answer, because the answer is silence
  rather than FORMERR, NOTIMP or a limit.
- **`rdnsr` has nothing to branch on**, so it stays `Request::from_bytes(&data).ok()?`
  — both failures are silence there. That asymmetry is the honest one: the
  variants exist because one caller uses them, not because both do.

**No failing-first regression test, for the second time in this section.** The
defect — `rdnsd` answering a response on its UDP port — was fixed at the call
site in `6c66816`, before this was filed, so there is nothing left to watch fail
(`CLAUDE.md` §1). The three behavioural tests that cover it
(`a_response_to_the_udp_port_is_not_answered`,
`a_response_sent_to_the_server_port_is_dropped`,
`a_response_is_dropped_rather_than_resolved`) were kept and still pass through
the new door, which is the point: they say what the behaviour is, and the type
says it cannot be forgotten.

Verified: `cargo test --workspace` 642/1/1/94/3 (+2 in `validation`, for the
constructor refusing QR=1 and for the two error variants staying apart); clippy
with `-D warnings` and `cargo fmt --all --check` clean; **all eighteen allocation
counts unchanged**. Also repaired on the way: a string literal in
`a_response_to_the_udp_port_is_not_answered`'s assertion message that a
search-and-replace had left with eighteen spaces in the middle of a sentence —
§12's warning about `format_strings` being off, in the wild.

#### 14c. Seal `RecordData` — **done 2026-08-02**

**The one genuinely unlocked by #13.** `RecordData`'s fields are `pub`, and
**twenty sites construct one directly**, bypassing `from_wire` and
`from_parsed`. So "the RDATA is well formed for this TYPE" is not an invariant,
which is why `RecordData::parse` returns a `Result` at all — a caller can build
`RecordData { rtype: A, rdata: <seventeen bytes> }` and nothing objects until
something tries to read it.

Sealing the pair only *means* anything now that `rtype` is an [`Rtype`] rather
than a `u16` anyone can invent, which is why this was not worth doing before
13c. Cost: twenty constructions become constructor calls, and eleven
`.rdata.rdata` reads become an accessor.

**Done**, and it cost more than the estimate in one place and less in another.

- **"Twenty constructions" was fourteen** — counted this time, with
  `grep -rn 'RecordData {'`, which is what the estimate should have been in the
  first place (§17's closing rule about reviewing a plan the way code gets
  reviewed). Eleven `.rdata.rdata` reads was exactly right, and the number the
  plan did not mention is the one that dominated the diff: **128**
  `.rdata.rtype` reads became `.rdata.rtype()`. Mechanical, but it is the bulk
  of the change.
- **Private fields in `lib.rs` would have sealed nothing.** `RecordData` lived
  in the crate root, and private *there* means visible to the crate root and
  every descendant module — the whole library, which is where all fourteen
  constructions were. A field is only sealed against the module it is declared
  in, so the type moved to `rdns/src/record_data.rs`, a module holding one
  struct on purpose. The plan missed this entirely, and it is the part that
  decides whether the item is worth doing at all.
- **A third door was needed.** `from_wire` and `from_parsed` do not cover
  "wire-format bytes some other code produced" — a signer building a DNSKEY, a
  zone file's RFC 3597 escape, a test. `RecordData::new(rtype, bytes)` is that
  door and it *checks*: build the pair, parse it, refuse a known type whose
  bytes are not that type. `zone.rs`'s generic-rdata path had already written
  that check out by hand, and now calls it instead (§7).
- **`ixfr::RecordKey` had to stop splitting the pair.** It carried `rtype` and
  `rdata` separately for its ordering and rebuilt a `RecordData` in
  `into_record`; after sealing, that rebuild would have gone through the checked
  constructor and re-parsed every changed record. It carries the whole
  `RecordData` now, with `Ord` written out rather than derived so that TYPE
  still sorts before class and TTL — which is the order records come out of a
  diff in, and therefore go onto the wire in.
- **It found a live defect before it found anything else**, recorded under #10
  above: the invariant it was about to assert is *false on the wire*, because
  RFC 2136 §2.4 and §2.5 spell six of their ten forms with RDLENGTH=0 and
  `ParsedRecord::decode` rejected that — so a legal UPDATE was FORMERR before
  `update.rs` ran. That is its own commit, landed first, with a regression test
  watched failing.

**One allocation count moved up, 922 to 924**, and the reason is written next to
the assertion rather than waved through (§10, and §13's gate pointed the other
way). `zone_signer::dnskey_rdata` now goes through the checked constructor,
whose parse allocates one `Vec` for a DNSKEY's public key; the measured zone is
signed with two keys and no NSEC3, so it is exactly two — arrived at by counting
the callers, not by rounding. Two allocations once per signing run, to make "the
RDATA is what its TYPE says" true by construction.

Verified: `cargo test --workspace` 646/1/1/94/3, against 643/1/1/94/3 before
(three new tests in `record_data`); clippy with `-D warnings` and
`cargo fmt --all --check` clean; the other seventeen allocation counts
unchanged.

#### Two that were checked and dropped, because a survey that only adds is not a survey

- **DNSSEC algorithm and digest type as `u8`.** Expected to be a finding; it is
  not. An algorithm this library cannot read falls through to
  `CryptoError::UnsupportedAlgorithm(other)` — already a data-carrying variant,
  already total, already what §2 asks for. A newtype would add a name and
  nothing else.
- **`if rcode > 0xfff` in `to_bytes`.** Reads like a runtime check standing in
  for an invariant, and is structurally unreachable from the wire: the extended
  RCODE byte is eight bits, so `(ext << 4) | (lo & 0xf)` cannot exceed 0xfff by
  construction. Only a hand-built `ResponseCode::Other` can trip it, and that is
  a caller's bug rather than a wire condition — which is what the check already
  says.

Genuinely low value, recorded so nobody re-derives them: the EDNS-version check
duplicated across `rdnsd` and `rdnsr` (two lines of policy each daemon owns),
and nine `bool` parameters (`dnssec_ok`, `is_tcp`, `deleting`).

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
treated as a query rather than answered NOTIMP — **fixed under #9c**), no
admission control on the UDP path (a task per datagram, unbounded — TCP has both
caps; **fixed 2026-08-01**, `--max-inflight-udp`), no rate limiting or
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

`rdnsr` (`rdnsr/src/main.rs`): query → EDNS sanity check (FORMERR / BADVERS) →
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

## Done so far

Newest first. The reasoning, RFC citations and verification for each are in the
commit message.

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
  identical on the Linux side.
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
  (`a5ce3ce`)
- **No task per UDP datagram on `rdnsd`, and a bound on `rdnsr`'s** — closes
  9d's admission-control item and 9e's 1,536-bytes-per-datagram one, which were
  the same call site. `rdnsd` answers inline from `--udp-workers` tasks sharing
  the socket; `rdnsr` keeps its spawn, because a recursion is seconds of waiting,
  and bounds it with `--max-inflight-udp`. Measured over 1,000 queries against a
  rebuilt `HEAD` on the same box: 7.45 MB in 34,487 blocks → 2.88 MB in 31,574,
  the task site gone and 996 responses built in 16 buffers. (`68e819d`)
- **Both daemons have log levels** — closes 9d's log-volume half. `--log-level`
  and `--quiet` on `rdnsd` and `rdnsr` through one `rdns::logging::init`, with
  `RUST_LOG` on top. Nothing per-packet is above `debug`, so 50 malformed
  datagrams cost **0 log lines** at the default level where they used to cost 50,
  and `format!` no longer runs for a line nobody wants. No in-process rate
  limiter: journald's per-unit one is in the README's unit instead. 11 crates,
  measured. (`4fb5cee`)
- **`rdnsd` compiles on Unix** — it had not since SIGHUP reloading was written,
  because `signals.next()` needed a `StreamExt` nothing imported and the module
  is `#[cfg(unix)]`. Found by running the suite on Linux for the first time.
  Fixed by using `tokio::signal::unix`, which `rdns::shutdown` already used, and
  deleting `signal-hook` and `signal-hook-tokio`. (`01f2b70`)
- **A secret file's mode is checked when it is read** — one
  `persist::ensure_private` for the TSIG and DNSSEC paths both, and
  `write_atomically_private` restricts the temporary file *before* the rename so
  a new private key is never briefly world-readable. (`c1c73d8`)
- **The zone load and the state fsync are off the runtime** — `spawn_blocking`
  for the reload, and the state write happens after the mutex guard is dropped
  rather than across the fsync. `load_zones_from_source` is honestly sync now; it
  was an `async fn` with no await in it. (`5ed8351`)
- **A reload no longer blocks every query for the length of its diffs** — planned
  under the read lock and recorded under the write lock, with a generation
  counter deciding whether the plan survived the gap. 99.5% of sampled queries
  were locked out during a reload before; ~0.3% after. (`0daf0c4`)
- **`--user`/`--group` closed as won't-fix** — privilege separation belongs to
  the service manager, and `User=` with an ambient capability is stronger than a
  setuid drop rather than equivalent to it. (`4f97660`)

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
