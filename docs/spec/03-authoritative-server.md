# 3. The authoritative server (`rdnsd`)

`rdnsd/src/main.rs`, `rdnsd/src/config.rs`, `rdnsd/src/control.rs`, and the
library modules `transfer`, `xfr`, `ixfr`, `notify`, `secondary`, `security`,
`validation`, `readiness`.

One process serves **UDP and TCP on the same host and port**. Both are
mandatory: a reply overflowing the client's UDP payload size goes out with TC=1
and the client retries over TCP (RFC 1035 §4.2.1), and zone transfers are TCP
only (RFC 5936 §4.2). Whichever loop fails first takes the process down, so it
never quietly serves one and not the other.

---

## 3.1 Admission: what happens to a packet before it is answered

In order. Every step that drops a packet does so **silently** unless noted.

### UDP (`udp_loop`, `Server::answer_datagram`)

1. **Receive.** A fixed pool of `--udp-workers` tasks share the socket and answer
   inline; there is no task per datagram. A receive error that
   `utils::recv_error_is_transient` recognises (ICMP reports, WSAEMSGSIZE, which
   arrives as `ErrorKind::Uncategorized`) continues the loop; anything else ends
   it and takes the process down.
2. **Rate limit** (`security::RateLimiter`, per source address). Over the limit:
   dropped, counted in `dns_rate_limited_total`. Dropping rather than REFUSING is
   deliberate — a reply to a spoofed source is what an amplifier sends.
3. **`AdmissionCheck::validate_packet(packet, is_tcp=false)`.** Fails:
   dropped, counted in `dns_validation_errors_total`.

   Note the caps this applies to a **request**: **512 octets** on UDP
   (`AdmissionLimits::max_udp_size`), at most 10 questions, and at most 4
   records in each of the answer, authority and additional sections. A UDP
   request over 512 octets is dropped **silently**, before anything reads it —
   RFC 1035 §4.2.1's 512 is the limit most servers apply to a request too, so
   this is conventional, but it is not visible on the wire and the only trace is
   a `debug` line and the counter.
4. **`validation::Request::from_bytes`.** This is *the door*: it parses and it
   refuses QR=1.
   - `RequestError::Wire(_)` → dropped.
   - `RequestError::NotAQuestion` → dropped. **A response MUST NOT be answered.**
     Two servers pointed at each other, or one spoofed datagram, is otherwise a
     packet loop neither end can see.
5. **TSIG** (`tsig::check_request`), before anything that could answer.
6. **Answer**, then **`security::ResponseLimiter::admit(ip, bytes)`** — a
   bytes-per-second budget metered on what *leaves*, with three verdicts:

   | verdict | when | what the client gets |
   |---|---|---|
   | `Send` | within budget | the answer |
   | `Truncate` | every `slip`-th over-budget response (**slip = 2**, BIND's own default), and any response from an untracked source once `max_tracked` is full | an empty TC=1 reply (`truncated_reply`) |
   | `Drop` | every other over-budget response | silence |

   The **slip** is the point: TC=1 carries no records, so it cannot amplify, and
   a real client reads it and retries over TCP where the handshake proves the
   address and the budget no longer applies (RFC 1035 §4.2.1) — while a spoofed
   source gets a reply only one time in `slip`. Going entirely silent would leave
   a legitimate client with a timeout and no idea that TCP would work; replying
   every time is what an amplifier does.

   A truncated reply is **still signed** if the request was: it is our answer to
   a question somebody authenticated.

### TCP (`tcp_loop`, `Server::serve_connection`, `Server::answer`)

Same steps 2–5, with `is_tcp=true` in step 3 and **no response budget** — a
query that completed a handshake has an address nobody can be reflecting at.

A connection carries any number of queries (RFC 7766 §6.2.1), answered
**concurrently** (§6.2.1.1) and bounded by `MAX_INFLIGHT_PER_CONNECTION`. One
task owns the write half, so replies never interleave; they may complete out of
order, which clients demultiplex on the transaction id.

---

## 3.2 Answering a question: `make_response`

Applied in this order.

### 3.2.1 EDNS-level rejections, before any zone lookup

| condition | rcode | OPT in reply |
|---|---|---|
| malformed EDNS option list | FORMERR (1) | bare version-0 OPT |
| EDNS version > 0 | BADVERS (16) | bare version-0 OPT (it carries the extended code's high bits) |

### 3.2.2 Opcode

Only QUERY reaches the zone lookup. NOTIFY is answered by the caller (§3.5) and
**UPDATE by §3.7** — both before `make_response`, because each is gated on
something a question is not and UPDATE changes what this server says next.
Everything else — STATUS, the obsolete IQUERY, anything unassigned — is **NOTIMP
with AA clear and the client's opcode echoed**, and the client's OPT record
mirrored.

(UPDATE was in that NOTIMP list until 2026-08-03.)

### 3.2.3 Class

`QCLASS ∈ {IN, ANY}` proceeds. Anything else is **REFUSED with AA clear**:
RFC 1034 §4.3.2 step 1 searches the zones *of the question's class*, and holding
none in that class is the same situation as a zone we do not serve. QCLASS=ANY is
not refused — RFC 1035 §3.2.5 makes it match any class, and IN is the only class
this server holds.

### 3.2.4 Transfer QTYPEs on UDP

| qtype | UDP behaviour |
|---|---|
| AXFR (252) | **FORMERR**. AXFR is defined over TCP alone (RFC 5936 §4.2); a whole zone does not fit a datagram and the protocol has no way to say "there is more" |
| IXFR (251) | a single SOA of the server's current version, per RFC 1995 §2, telling the client to come back over TCP. REFUSED if the zone is not served here |

The IXFR-over-UDP answer is always the single-SOA form. That is a deliberate
choice rather than a limitation: the ACL, the TSIG session and the multi-message
packing all live on the TCP path, and duplicating them here would be a second
implementation of the interesting parts.

### 3.2.5 Zone selection

`find_zone_for_query`: among zones whose origin contains the QNAME
(`utils::is_at_or_under`), the one with the **longest origin** wins — a server
holding both `example.com` and `sub.example.com` answers for the child from the
child's zone. The root zone contains everything.

**No zone: REFUSED with AA clear.** Not NXDOMAIN. NXDOMAIN is an assertion about
the DNS that a server holding nothing has no standing to make, and resolvers
cache it (RFC 2308). This matters more now that a zone can be *withdrawn*: an
expired secondary answering NXDOMAIN would take its zone off the internet for as
long as anything cached the answer.

### 3.2.6 RFC 1034 §4.3.2, in order — `resolve_in_zone`

The four cases are tried **in this order at every name**, and the order is the
point: getting the first one last is how a parent answers NXDOMAIN for a child's
names.

1. **The zone's authority ends here.** `Zone::delegation_for(name)` is `Some`.
   → `Outcome::Referral { cut }`, unless the question is `DS` *at* the cut — the
   DS is the parent's own statement about the child and is answered here
   (RFC 4035 §3.1.4.1). Mid-CNAME-chain a delegation yields
   `Outcome::ChainLeftZone` instead: stopping with what we hold costs one round
   trip and cannot be wrong, whereas answering from glue below the cut would
   serve occluded data as authoritative.
2. **The name has the data.** `Zone::query(name, qtype)` is non-empty →
   `Outcome::Answer`.
3. **The name is an alias.** A CNAME at the name, and the question is not for
   CNAME itself (an alias asked for by name is the data). Push the alias onto the
   chain and restart at the target. If the target leaves the zone, or repeats a
   name already visited, → `Outcome::ChainLeftZone`.
4. **No such data.** → `Outcome::Negative { name, kind }` with the `NameKind`
   that decides NXDOMAIN against NODATA.

Bounded at `MAX_CNAME_HOPS = 16`, plus a visited-set that stops a two-record
loop.

### 3.2.7 Building each outcome

| outcome | answer section | authority | additional | AA |
|---|---|---|---|---|
| `Referral` | — | the cut's NS RRset, **unsigned** (it is the child's data, RFC 4035 §2.2) + DS or its denial when DO | in-bailiwick glue only | **clear** |
| `Answer` | the chain's CNAMEs, then the records at the end, echoed under the *queried* name (RFC 1034 §4.3.3) + RRSIGs when DO | wildcard denial when the answer was synthesized | — | set |
| `Negative` | the chain's CNAMEs | the apex SOA + the proof when DO | — | set |
| `ChainLeftZone` | the chain's CNAMEs, nothing else | — | — | set |

- **AA is clear on a referral** (RFC 1035 §4.1.1). With AA set, RFC 8020 has
  every resolver cache "the whole subtree does not exist".
- **Glue is in-bailiwick only.** An address for a nameserver under this zone is a
  hint we are entitled to give; one for a name in somebody else's zone is an
  assertion about their data, which a resolver worth anything discards
  (RFC 1034 §4.2.1).
- **`ChainLeftZone` is NOERROR, not NXDOMAIN**: we know nothing about the target,
  and saying it does not exist would take it off the internet for as long as
  anything cached the answer.
- **A wildcard answer is not finished when its signature is attached** — it also
  owes a denial of the name actually asked for (RFC 4035 §3.1.3). See
  `04-dnssec.md` §4.3.

### 3.2.8 Negative-answer TTL

The SOA in the authority section goes out at **`min(SOA MINIMUM, the SOA
record's own TTL)`** (RFC 2308 §3), and so does the RRSIG beside it. An SOA that
will not parse caps at zero: the client asks again rather than caching a "no" we
cannot bound.

### 3.2.9 EDNS mirroring

An OPT record is included **only when the client sent one** (RFC 6891 §6.1.1),
advertising `RDNSD_PAYLOAD_SIZE`, with DO echoed when it was asked for
(RFC 3225 §3). This applies on **every** reply path including NOTIMP and every
error — `error_bytes` and the NOTIMP branch both do it.

---

## 3.3 Response codes this server emits

| rcode | when |
|---|---|
| NOERROR | an answer, a NODATA, a referral, a chain that left the zone; an UPDATE that was applied, or that changed nothing (§3.4.2.5) |
| NXDOMAIN | `NameKind::NotFound` inside a zone we serve; an UPDATE prerequisite of §2.4.4's form that did not hold (§3.2.4) |
| FORMERR | a malformed EDNS option list; AXFR over UDP; an UPDATE that breaks §3.1 or §3.4.1's prescan |
| NOTIMP | any opcode but QUERY, NOTIFY and UPDATE |
| REFUSED | a class we do not serve; a name in no zone we hold; a transfer the ACL or key scope denies; an UPDATE that is unsigned, outside its key's scope, for a zone we replicate, or for a zone we cannot write |
| NOTAUTH | a transfer or NOTIFY for a zone not served here; a TSIG that did not verify; an UPDATE for a zone we are not authoritative for (RFC 2136 §3.1.1) |
| SERVFAIL | a transfer that would not build or serialize; an UPDATE that could not be read, written or signed (RFC 2136 §3.4.2.1) |
| BADVERS | EDNS version > 0 |
| NOTZONE | an UPDATE record outside the zone its own Zone section names (RFC 2136 §3.4.1) |
| YXDOMAIN, YXRRSET, NXRRSET | the other three UPDATE prerequisite failures (RFC 2136 §3.2) |

---

## 3.4 Zone transfer — the server side

### Authorization

**Authentication and authorization are two questions.** A verified TSIG MAC
answers "who are you". It says nothing about "what may you do".

```
if a TSIG session exists and the key is scoped to zones not containing <apex>:
        REFUSED   (signed)
else if no TSIG session and the source address is not in --allow-transfer:
        REFUSED   (unsigned — there is no session to sign with)
else:
        allowed
```

- **Checked before the zone is looked up and before any message is built.** The
  point of an authorization check is that the work does not happen.
- **Authorized against the apex**, exactly. A transfer hands over a whole zone,
  so a rule matching anything less specific authorizes more than it names; a
  child of a listed zone is refused.
- The check hangs off the `TsigSession` rather than re-looking-up the key by
  name: the session *is* the answer to "which key was this", and a key name is
  attacker-supplied until the MAC verifies.
- **An unscoped key still transfers everything.** Narrowing that default would
  stop every working deployment on a version bump with no warning. Instead the
  startup banner prints what each key may transfer, so the decision is
  reviewable rather than invisible.
- **A refused authenticated request is REFUSED, not NOTAUTH**: the peer proved
  who it is and the answer is no, which is a policy decision about this server
  rather than a statement about the zone's authority.
- **Every error reply on this path is signed if the request was**
  (RFC 8945 §5.3), including NOTAUTH, REFUSED and SERVFAIL. An unsigned refusal
  is reported by dnspython as "the TSIG record is malformed", which sends the
  reader after a key mismatch that does not exist.

Every attempt is logged, allowed or not, with which of the two granted it.

### AXFR (RFC 5936)

- The zone name is matched **exactly against the origin**, not by enclosing-zone
  lookup: transferring `example.com.` because `www.example.com.` was asked for
  would hand over a zone nobody named.
- The stream opens with the apex SOA and closes with the same SOA, and that SOA
  appears **exactly twice** — the apex SOA is skipped in the middle, because a
  client seeing the closing SOA early stops reading there.
- Records go across under their absolute names, wildcards included.
- Split into messages of about **16 KiB** (`AXFR_TARGET_MESSAGE_SIZE`), by a
  size estimate that ignores compression and so can only be too large. Each
  message is a well-formed authoritative answer that repeats the question
  (RFC 5936 §2.2.1 permits omitting it; repeating is the simpler half).
- The OPT record goes on the **first message only**, before the TSIG.
- A zone with no apex SOA cannot be transferred: SERVFAIL.
- **A serialization failure abandons the whole transfer.** Half a transfer is
  worse than none — the client cannot tell a stream that stopped early from one
  that finished.

### IXFR (RFC 1995)

Gated **identically** to AXFR, because an IXFR may answer with the whole zone
(§4), so a weaker policy would be no policy.

`ixfr::ixfr_response` returns one of:

| result | wire shape |
|---|---|
| `UpToDate` | one SOA — the client already has this version |
| `Incremental { steps, records }` | the delete/add SOA-framed difference chain |
| `FullTransfer { why }` | the whole zone, when no chain covers the client's serial |

The delta log is read **under the zone lock**, so the increments and the zone
they are increments of are the same version. Taken separately, a reload between
the two reads would produce a chain that does not match its SOA framing.

A zone's deltas are forgotten whenever the zone stops being served.

**They survive a restart** since 2026-08-03 (`rdns::journal`, `TODO.md` #7 step
6). Each version step is written beside the zone as the RFC 1995 difference
sequence a client would receive, and read back at startup. A journal that will
not parse is a warning and an empty history, not a refusal to start: losing it
costs some secondaries a full transfer, which §4 permits at any time. A journal
whose steps do not link end to end *is* refused, because a gap would hand a
secondary a version that never existed with a serial saying it is current — and
one whose last step does not reach the serial actually loaded is discarded, since
the zone moved past it by some route the journal did not see.

Before that, a restart forgot them and every secondary asking for an increment
got a full transfer — correct, permitted unconditionally by §4, and
self-correcting. What changed is not that behaviour's correctness but its cost:
with dynamic UPDATE served, the zone moves *between* reloads, so a restart
discarded work nothing would recreate, and `MAX_DELTAS_PER_ZONE` (32) is a
generous history when an operator edits a file and thirty-two updates when a DHCP
client writes.

---

## 3.5 NOTIFY (RFC 1996)

### Sending

`--also-notify <addr[:port]>` (global) and `[zones."x"].also-notify` (per zone).
A NOTIFY is sent on zone load — at startup and on every reload — for every zone
**whose serial moved forward**, compared with `Serial::is_newer_than`.

> **Deviation D-3 — fixed 2026-08-03.** ~~The transaction id is derived from
> `SystemTime`'s `subsec_nanos()`, so two NOTIFYs in one clock tick share an
> id.~~ One `utils::rand_id`, `rand::thread_rng()`, called by both this and
> `xfr`. See `07-rfc-conformance.md`.

### Receiving

```
if the zone is one we replicate:
        if the peer's address is one of its masters:  NOERROR, wake the refresh task now
        else:                                          REFUSED  (a NOTIFY costs its recipient a transfer)
else if we serve the zone as primary:                  NOTAUTH  ("this server is its primary")
else:                                                  NOTAUTH  ("not a zone served here")
```

Waking uses `Notify::notify_one`, which leaves a permit for a task that is
mid-transfer, so a NOTIFY arriving at a busy moment is not lost.

> **Deviation D-4 — fixed 2026-08-03.** ~~The zone-name lookup key is built with
> `str::to_lowercase`, which folds U+212A KELVIN SIGN onto `k` where RFC 4343
> requires an ASCII-only fold.~~ Both this lookup and its matching insert go
> through `utils::absolute_lowered` now. See `07-rfc-conformance.md`.

---

## 3.6 The secondary role

`--secondary zone@master[:port][#tsig-key-name]`, repeatable; repeat the same
zone for more masters. Requires `--zone-dir`, because a fetched zone is written
there under its own name and loaded by the ordinary path on the next start.

### The refresh loop (one task per `(zone, master)` pair)

```
loop {
    refresh_once()                      // SOA probe, compare, transfer if newer
    timers = the zone we now hold        // read AFTER the refresh
    on success: sleep REFRESH
    on failure: expire_if_out_of_contact(); sleep RETRY
    interruptible by a NOTIFY or by shutdown
}
```

The timers are read **after** the refresh, not before, because the refresh may
have just installed the zone that defines them. Read first, the very first
transfer is followed by the default hour instead of the REFRESH the zone asks
for.

Defaults when no zone is held yet: REFRESH = `DEFAULT_REFRESH_SECS`,
RETRY = `MIN_TIMER_SECS`, EXPIRE = `u64::MAX` (a zone never reached cannot
expire — there is nothing to withdraw).

No `Busy` claim is held across the sleep: a refresh timer is hours long and the
shutdown drain must not wait on one.

### Deciding to transfer

`secondary::is_newer` → `Serial::is_newer_than`. RFC 1982 arithmetic, so a
wrapped increment is correctly read as newer.

### EXPIRE — withdrawing a zone

Two paths, and both must exist:

1. **`expire_if_out_of_contact`**, on every failed refresh. If the last
   successful contact is older than the zone's EXPIRE, the zone is removed from
   the served map, its IXFR deltas are forgotten, and its metric gauges are
   forgotten. Logged at **WARN** — this is what an alert is built on and must not
   need a level turned up to be seen.
2. **`withdraw_unvouched_zones`**, after **every** fill of the zone map from
   disk — startup *and* every reload. Without this, a SIGHUP re-read every
   `.zone` file and served it again with AA set, so a zone correctly withdrawn
   because its primary had been unreachable for a week came straight back.
   Expiry that lasts only until the next deploy is not expiry.

`withdraw_unvouched_zones` withdraws on **two** conditions, and the second is the
subtle one:

- the recorded contact is older than EXPIRE; **or**
- there is **no record of contact at all** while the zone is loaded from disk.
  A missing sidecar, an unreadable one, or an entry for a different master all
  land here. Unknown age means "do not serve", because forgetting the
  last-contact time *is* the difference between a withdrawn zone and a stale one
  served with AA set. The zone returns at the first successful transfer.

A zone we hold but do not replicate is never touched — the loop is over the
`--secondary` specs.

### The state sidecar

`rdns/src/secondary.rs`. A text file beside the zones recording, per
`(zone, master)`, the serial and the timestamp of the last successful transfer.
`StateFile::load` returns empty and never fails, which is right for a cache and
is precisely why `withdraw_unvouched_zones` treats "no entry" as expiry rather
than trusting it.

### Readiness

`/readyz` returns 503 until **every** `--secondary` zone has transferred at least
once, and 200 immediately on a primary, whose zones were all loaded, signed and
verified before anything bound a socket. A one-way latch (`rdns/src/readiness.rs`).

---

## 3.7 Dynamic UPDATE (RFC 2136)

Served since 2026-08-03, on both transports. `rdns::update` reads the message and
applies the changes; `rdnsd` authorizes, persists and installs.

### The order of the checks

It is the RFC's, and it is not arbitrary — each one exists to keep the next from
running, and authorization comes before the zone is even loaded.

| step | check | failure |
|---|---|---|
| §3.1 | one zone in the Zone section, and it is an SOA | FORMERR |
| §3.4.1 | prescan: no meta-type added, nothing outside the named zone | FORMERR / **NOTZONE** |
| §3.3 | the request is TSIG-signed | **REFUSED** |
| §3.3 | the key's own update scope covers this apex | **REFUSED** |
| §3.1.1 | the zone is one this server is authoritative for | **NOTAUTH** |
| — | the zone is not one this server *replicates* | **REFUSED** |
| — | the zone has a file this server can write | **REFUSED** |
| §3.2 | every prerequisite holds | NXRRSET / YXRRSET / NXDOMAIN / YXDOMAIN |
| §3.4.2 | apply | NOERROR, or SERVFAIL on a system failure (§3.4.2.1) |

Two of those deserve stating out loud.

**A zone this server does not hold is NOTAUTH, not REFUSED** — the opposite of
the query path's rule (§3.2.5, and `CLAUDE.md` §8). The two answer different
questions: a query asks this server to speak about a name, while an UPDATE names
the zone it belongs to and asks whether this server is its authority. RFC 2136
§3.1.1 gives that its own code.

**An unsigned UPDATE is refused outright, with no address-based alternative.**
`--allow-transfer` exists because a transfer is a read and an address is a weak
but real answer to "who is this". A write is not something to grant on a source
address that UDP makes nobody prove.

### Authorization

Per key, and **denied by default** — which is the opposite of the transfer scope
beside it. An unscoped key transfers every zone, because narrowing that would
stop transfers on a working deployment on a version bump; nothing had ever served
an UPDATE, so there was no deployment to break, and a transfer hands over a copy
where an update rewrites the original. Reusing the transfer scope would have
handed write access to every zone to every key already configured.

`rdns::tsig::UpdatePolicy` is three states — `Denied`, `Zones(..)`, `Any` —
rather than a `Vec` with an overloaded empty case, so "no zones" and "all zones"
cannot be confused. Spelled as a fifth field of `--tsig-key`, or `update-zones`
in the config file. The check hangs off the verified `TsigSession` rather than a
second lookup by key name, because a key name is attacker-supplied until the MAC
verifies.

### What applying does

`update::apply` rebuilds the zone rather than editing it: `Zone`'s index holds
positions into its record vector, so removing a record in place invalidates every
later one. Changes apply **in order, each to the result of the last**, which is
what §3.4.2.7's pseudocode describes and is observable — a delete-then-add at one
name leaves what the add put there.

The §3.4.2 rules encoded: CNAME exclusivity in both directions (excluding RRSIG,
NSEC and NSEC3, which RFC 4035 §2.5 permits beside a CNAME); the SOA serial rule;
duplicate-RDATA replacement, which is how an UPDATE changes a TTL; the apex SOA
and NS protections in both halves of §3.4.2.3; and §3.4.2.4's last-NS
protection, which asks what the deletion would *leave* rather than whether the
RRset is currently a singleton.

Changes the RFC requires be ignored are reported and logged at INFO. §3.4.2.5
signals NOERROR regardless, so without that the client is told its write went
through, the record is not there, and nothing anywhere says why.

> **Where the prose and the pseudocode disagree, the prose wins.** §3.4.2.2
> ignores an SOA whose serial is "lower ... than or equal to" the current one;
> §3.4.2.7 spells the same test as `zone.serial > rr.serial`, which *accepts* an
> equal serial. The pseudocode's reading would let an UPDATE rewrite MNAME, RNAME
> or the timers while leaving the version number where it was, and §3.6 calls it
> "imperative that the zone's contents and the SOA's SERIAL be tightly
> synchronized".

### The serial

§3.6's automatic bump fires **only when something changed**. The increment is
owed "prior to including the SOA or any modified resource records", and an UPDATE
that modified nothing has none; bumping unconditionally would make a DHCP
client's retried deletion cost a re-signing run and an IXFR to every secondary.

For a signed zone the served serial is the file's plus a time term
(`zone_signer::signed_serial`). Because that term is **added** rather than
`max`ed, an UPDATE's `+1` survives signing as a `+1` in the served number. Under
a `max` every update inside one hour would have served one serial and no
secondary would have fetched any of them.

### Persistence, and why it is a precondition

**The zone file is written before the client is told the update succeeded.** The
obvious reason is a restart, and it is not the binding one: the re-signing timer
*reloads every zone from its file* — it must, because re-signing the in-memory
copy would apply the serial derivation to its own output and compound it every
cycle — so a change that lived only in the zone map is discarded within one
re-signing interval, silently. An in-memory-only UPDATE would be a write with a
timer on it.

So an UPDATE is a zone-file edit followed by the load path: read the zone as the
file has it, check §3.2 against that, apply, write atomically, sign, install.
Write-then-install is the safe order — a crash between them loses nothing,
because the file holds the new version and the next load picks it up.

§3.7's atomicity is one mutex held across the whole read-modify-write.

### Re-signing

A signed zone is re-signed **incrementally**, carrying forward every signature
whose RRset did not move (`zone_signer::sign_zone_incrementally`). This is not
only about CPU: every RRSIG's inception and expiration derive from the run's
`signed_at`, so a full re-sign produces different RDATA for *every* signature,
and `ixfr::diff` — comparing whole records, correctly — puts all of them in the
delta. Measured on the signer's test zone: a one-record UPDATE produced a
**52-record** delta out of 53 records before, and **10** after.

The denial chain is still built in full, and that is the design rather than a
shortcut declined. An NSEC's bitmap lists every type at its name and its `next`
names its successor, so inserting one name changes the denial record at that name
*and* at its predecessor. Building the chain and then asking which records came
out byte-identical never computes a neighbour set, so it cannot compute one
wrongly — in the measurement above it picked up the predecessor unprompted.

A signature is carried forward only when the RRset is identical as a *set*, at
least one signature existed, the signing keys are unchanged by key tag, and
nothing carried has already expired. **Being near expiry is deliberately not a
condition**: refreshing here would re-sign every stale RRset in the zone on any
single UPDATE, and would let update traffic stand in for the re-signing timer, so
a zone with a dead timer would degrade differently depending on whether anyone
was writing to it.

---

## 3.8 Reload

Triggered by `SIGHUP` (Unix), by `rdnsctl reload`, or by the zone-maintenance
timer (which also re-signs; see `04-dnssec.md` §4.1).

**All or nothing.** `Reloading::load` reads every zone, signs every zone that has
a key, verifies every signature, and installs the new set only if the whole set
came through. A failure leaves the previously served zones in place and reports
why — `rdnsctl reload` exits 1 with the parse error, unlike `kill -HUP`, which
cannot say whether it worked.

Sequence:

1. Read and parse every zone **on a blocking thread** (`spawn_blocking`) — the
   read, the parse and a full signing run must not happen on a worker that is
   also answering queries.
2. `plan_reload` diffs the new set against the old **under the read lock**.
3. Install **under the write lock**, briefly. Computing under the write lock
   would block every query for the sum of the diffs.
4. `withdraw_unvouched_zones` (§3.6).
5. `note_serials` updates the per-zone metric gauges; zones no longer present are
   *forgotten*, not frozen.
6. NOTIFY every zone whose serial moved forward (§3.5).

---

## 3.9 The control socket

`--control-socket <path>`, **Unix only** — `tokio` has no `UnixListener` on
Windows, so it is refused there at startup rather than accepted and ignored.

Created mode **0600**: filesystem permissions are the authentication, which is
what `knotc`, `pdns_control` and `unbound-control` do. The two servers that put a
control channel on TCP put an HMAC or a client certificate in front of it; nobody
ships an unauthenticated control port. This is also why these commands are not on
`--metrics-listen`, where `reload` would be a POST with no credential.

Protocol (`rdns/src/control.rs`): one command line in, a status line
(`+OK` / `-ERR`) and a body out, then close. Deliberately plain text — the day
the control socket is needed is the day the box has nothing else installed on
it, and `printf 'status\n' | socat - UNIX-CONNECT:...` is a working client.

| command | does |
|---|---|
| `status` (default) | zones, serials, last transfer, uptime, counters |
| `reload` | a full reload, answering whether it worked; server-side bound 120 s |
| `dump <zone>` | the zone in presentation form |
| `version` | `rdnsd <version>` |
| `help`, empty | usage |

Request bound: `control::MAX_REQUEST` = 4096 bytes.

`rdnsctl` exit codes: **0** the command worked, **1** the server refused it,
**2** we could not ask. Three and not two, because a script retrying a `reload`
needs to tell "the server said no" (a config to fix) from "there was no server"
(a daemon to start).
