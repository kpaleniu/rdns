# 3. The authoritative server (`rdnsd`)

`rdnsd/src/main.rs`, `config.rs`, `control.rs`, and the library modules
`transfer`, `xfr`, `ixfr`, `notify`, `secondary`, `security`, `validation`,
`readiness`.

One process serves UDP and TCP on the same host and port. Whichever loop fails
first takes the process down.

---

## 3.1 Admission: what happens to a packet before it is answered

In order. Every step that drops a packet does so silently unless noted.

### UDP (`udp_loop`, `Server::answer_datagram`)

1. Receive. A fixed pool of `--udp-workers` tasks share the socket and answer
   inline; there is no task per datagram. A receive error that
   `utils::recv_error_is_transient` recognises (ICMP reports, WSAEMSGSIZE, which
   arrives as `ErrorKind::Uncategorized`) continues the loop; anything else ends
   it and takes the process down.
2. Rate limit (`security::RateLimiter`, per source address). Over the limit:
   dropped, counted in `dns_rate_limited_total`. Dropped rather than REFUSED — a
   reply to a spoofed source amplifies.
3. `AdmissionCheck::validate_packet(packet, is_tcp=false)`. Fails: dropped,
   counted in `dns_validation_errors_total`. Caps applied to a request: 512
   octets on UDP (`AdmissionLimits::max_udp_size`), at most 10 questions, at most
   4 records in each of the answer, authority and additional sections. A UDP
   request over 512 octets is dropped silently; the only trace is a `debug` line
   and the counter.
4. `validation::Request::from_bytes` — parses, and refuses QR=1.
   - `RequestError::Wire(_)` → dropped.
   - `RequestError::NotAQuestion` → dropped. A response MUST NOT be answered.
5. TSIG (`tsig::check_request`), before anything that could answer.
6. Answer, then `security::ResponseLimiter::admit(ip, bytes)` — a
   bytes-per-second budget metered on what leaves:

   | verdict | when | what the client gets |
   |---|---|---|
   | `Send` | within budget | the answer |
   | `Truncate` | every `slip`-th over-budget response (slip = 2), and any response from an untracked source once `max_tracked` is full | an empty TC=1 reply (`truncated_reply`) |
   | `Drop` | every other over-budget response | silence |

   A truncated reply is still signed if the request was.

### TCP (`tcp_loop`, `Server::serve_connection`, `Server::answer`)

Same steps 2–5, with `is_tcp=true` in step 3 and no response budget.

A connection carries any number of queries (RFC 7766 §6.2.1), answered
concurrently (§6.2.1.1) and bounded by `MAX_INFLIGHT_PER_CONNECTION`. One task
owns the write half, so replies never interleave; they may complete out of order,
which clients demultiplex on the transaction id.

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
UPDATE by §3.7, both before `make_response`. Everything else — STATUS, IQUERY,
anything unassigned — is NOTIMP with AA clear, the client's opcode echoed and the
client's OPT record mirrored.

### 3.2.3 Class

`QCLASS ∈ {IN, ANY}` proceeds. Anything else is REFUSED with AA clear
(RFC 1034 §4.3.2 step 1 searches the zones of the question's class). QCLASS=ANY
matches any class (RFC 1035 §3.2.5), and IN is the only class served.

### 3.2.4 Transfer QTYPEs on UDP

| qtype | UDP behaviour |
|---|---|
| AXFR (252) | FORMERR — AXFR is TCP only (RFC 5936 §4.2) |
| IXFR (251) | a single SOA of the server's current version (RFC 1995 §2), telling the client to come back over TCP. REFUSED if the zone is not served here |

The IXFR-over-UDP answer is always the single-SOA form.

### 3.2.5 Zone selection

`find_zone_for_query`: among zones whose origin contains the QNAME
(`utils::is_at_or_under`), the one with the longest origin wins. The root zone
contains everything.

No zone: REFUSED with AA clear, not NXDOMAIN.

### 3.2.6 RFC 1034 §4.3.2, in order — `resolve_in_zone`

The four cases are tried in this order at every name:

1. The zone's authority ends here. `Zone::delegation_for(name)` is `Some` →
   `Outcome::Referral { cut }`, unless the question is `DS` *at* the cut, which
   is answered here (RFC 4035 §3.1.4.1). Mid-CNAME-chain a delegation yields
   `Outcome::ChainLeftZone` instead.
2. The name has the data. `Zone::query(name, qtype)` is non-empty →
   `Outcome::Answer`.
3. The name is an alias. A CNAME at the name, and the question is not for CNAME
   itself. Push the alias onto the chain and restart at the target. If the target
   leaves the zone, or repeats a name already visited, → `Outcome::ChainLeftZone`.
4. No such data → `Outcome::Negative { name, kind }` with the `NameKind` that
   decides NXDOMAIN against NODATA.

Bounded at `MAX_CNAME_HOPS = 16`, plus a visited-set that stops a two-record loop.

### 3.2.7 Building each outcome

| outcome | answer section | authority | additional | AA |
|---|---|---|---|---|
| `Referral` | — | the cut's NS RRset, unsigned (RFC 4035 §2.2) + DS or its denial when DO | in-bailiwick glue only | clear (RFC 1035 §4.1.1) |
| `Answer` | the chain's CNAMEs, then the records at the end, echoed under the *queried* name (RFC 1034 §4.3.3) + RRSIGs when DO | wildcard denial when the answer was synthesized (RFC 4035 §3.1.3) | — | set |
| `Negative` | the chain's CNAMEs | the apex SOA + the proof when DO | — | set |
| `ChainLeftZone` | the chain's CNAMEs, nothing else | — | — | set |

Glue is in-bailiwick only (RFC 1034 §4.2.1). `ChainLeftZone` is NOERROR, not
NXDOMAIN.

### 3.2.8 Negative-answer TTL

The SOA in the authority section goes out at `min(SOA MINIMUM, the SOA record's
own TTL)` (RFC 2308 §3), and so does the RRSIG beside it. An SOA that will not
parse caps at zero.

### 3.2.9 EDNS mirroring

An OPT record is included only when the client sent one (RFC 6891 §6.1.1),
advertising `RDNSD_PAYLOAD_SIZE`, with DO echoed when it was asked for
(RFC 3225 §3). This applies on every reply path, NOTIMP and every error included.

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

```
if a TSIG session exists and the key is scoped to zones not containing <apex>:
        REFUSED   (signed)
else if no TSIG session and the source address is not in --allow-transfer:
        REFUSED   (unsigned — there is no session to sign with)
else:
        allowed
```

- Checked before the zone is looked up and before any message is built.
- Authorized against the apex, exactly: a child of a listed zone is refused.
- The check hangs off the `TsigSession` rather than re-looking-up the key by
  name.
- An unscoped key transfers everything. The startup banner prints what each key
  may transfer.
- A refused authenticated request is REFUSED, not NOTAUTH.
- Every error reply on this path is signed if the request was (RFC 8945 §5.3),
  NOTAUTH, REFUSED and SERVFAIL included.

Every attempt is logged, allowed or not, with which of the two granted it.

### AXFR (RFC 5936)

- The zone name is matched exactly against the origin, not by enclosing-zone
  lookup.
- The stream opens with the apex SOA and closes with the same SOA, and that SOA
  appears exactly twice — it is skipped in the middle.
- Records go across under their absolute names, wildcards included.
- Split into messages of about 16 KiB (`AXFR_TARGET_MESSAGE_SIZE`) by a size
  estimate that ignores compression and so can only be too large. Each message is
  a well-formed authoritative answer that repeats the question.
- The OPT record goes on the first message only, before the TSIG.
- A zone with no apex SOA cannot be transferred: SERVFAIL.
- A serialization failure abandons the whole transfer.

### IXFR (RFC 1995)

Gated identically to AXFR. `ixfr::ixfr_response` returns one of:

| result | wire shape |
|---|---|
| `UpToDate` | one SOA — the client already has this version |
| `Incremental { steps, records }` | the delete/add SOA-framed difference chain |
| `FullTransfer { why }` | the whole zone, when no chain covers the client's serial |

The delta log is read under the zone lock, so the increments and the zone they
are increments of are the same version. A zone's deltas are forgotten whenever
the zone stops being served. `MAX_DELTAS_PER_ZONE` is 32.

Deltas survive a restart (`rdns::journal`): each version step is written beside
the zone as the RFC 1995 difference sequence a client would receive, and read
back at startup.

- A journal that will not parse is a warning and an empty history, not a refusal
  to start.
- A journal whose steps do not link end to end is refused.
- A journal whose last step does not reach the serial actually loaded is
  discarded.

---

## 3.5 NOTIFY (RFC 1996)

### Sending

`--also-notify <addr[:port]>` (global) and `[zones."x"].also-notify` (per zone).
Sent on zone load — at startup and on every reload — for every zone whose serial
moved forward, compared with `Serial::is_newer_than`. Transaction ids come from
`utils::rand_id`.

> Deviation D-3 — fixed 2026-08-03. ~~The transaction id is derived from
> `SystemTime`'s `subsec_nanos()`, so two NOTIFYs in one clock tick share an
> id.~~ See `07-rfc-conformance.md`.

### Receiving

```
if the zone is one we replicate:
        if the peer's address is one of its masters:  NOERROR, wake the refresh task now
        else:                                          REFUSED
else if we serve the zone as primary:                  NOTAUTH  ("this server is its primary")
else:                                                  NOTAUTH  ("not a zone served here")
```

Waking uses `Notify::notify_one`, which leaves a permit for a task that is
mid-transfer.

> Deviation D-4 — fixed 2026-08-03. ~~The zone-name lookup key is built with
> `str::to_lowercase`, which folds U+212A KELVIN SIGN onto `k` where RFC 4343
> requires an ASCII-only fold.~~ Both this lookup and its matching insert go
> through `utils::absolute_lowered` now. See `07-rfc-conformance.md`.

---

## 3.6 The secondary role

`--secondary zone@master[:port][#tsig-key-name]`, repeatable; repeat the same
zone for more masters. Requires `--zone-dir`.

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

The timers are read after the refresh, because the refresh may have just
installed the zone that defines them.

Defaults when no zone is held yet: REFRESH = `DEFAULT_REFRESH_SECS`,
RETRY = `MIN_TIMER_SECS`, EXPIRE = `u64::MAX`.

No `Busy` claim is held across the sleep.

### Deciding to transfer

`secondary::is_newer` → `Serial::is_newer_than`, RFC 1982 arithmetic.

### EXPIRE — withdrawing a zone

Two paths:

1. `expire_if_out_of_contact`, on every failed refresh. If the last successful
   contact is older than the zone's EXPIRE, the zone is removed from the served
   map, its IXFR deltas are forgotten, and its metric gauges are forgotten.
   Logged at WARN.
2. `withdraw_unvouched_zones`, after every fill of the zone map from disk —
   startup and every reload.

`withdraw_unvouched_zones` withdraws when either:

- the recorded contact is older than EXPIRE; or
- there is no record of contact at all while the zone is loaded from disk — a
  missing sidecar, an unreadable one, or an entry for a different master. The
  zone returns at the first successful transfer.

A zone we hold but do not replicate is never touched.

### The state sidecar

`rdns/src/secondary.rs`. A text file beside the zones recording, per
`(zone, master)`, the serial and the timestamp of the last successful transfer.
`StateFile::load` returns empty and never fails, which is why
`withdraw_unvouched_zones` treats "no entry" as expiry.

### Readiness

`/readyz` returns 503 until every `--secondary` zone has transferred at least
once, and 200 immediately on a primary. A one-way latch
(`rdns/src/readiness.rs`).

---

## 3.7 Dynamic UPDATE (RFC 2136)

On both transports. `rdns::update` reads the message and applies the changes;
`rdnsd` authorizes, persists and installs.

### The order of the checks

| step | check | failure |
|---|---|---|
| §3.1 | one zone in the Zone section, and it is an SOA | FORMERR |
| §3.4.1 | prescan: no meta-type added, nothing outside the named zone | FORMERR / NOTZONE |
| §3.3 | the request is TSIG-signed | REFUSED |
| §3.3 | the key's own update scope covers this apex | REFUSED |
| §3.1.1 | the zone is one this server is authoritative for | NOTAUTH |
| — | the zone is not one this server *replicates* | REFUSED |
| — | the zone has a file this server can write | REFUSED |
| §3.2 | every prerequisite holds | NXRRSET / YXRRSET / NXDOMAIN / YXDOMAIN |
| §3.4.2 | apply | NOERROR, or SERVFAIL on a system failure (§3.4.2.1) |

A zone this server does not hold is NOTAUTH, not REFUSED — the opposite of the
query path's rule (§3.2.5); RFC 2136 §3.1.1 gives it its own code. An unsigned
UPDATE is refused outright, with no address-based alternative.

### Authorization

Per key, denied by default. `rdns::tsig::UpdatePolicy` is three states —
`Denied`, `Zones(..)`, `Any` — so "no zones" and "all zones" cannot be confused.
Spelled as a fifth field of `--tsig-key`, or `update-zones` in the config file.
The check hangs off the verified `TsigSession`, not a second lookup by key name.

### What applying does

`update::apply` rebuilds the zone rather than editing it, because `Zone`'s index
holds positions into its record vector. Changes apply in order, each to the
result of the last (§3.4.2.7), so a delete-then-add at one name leaves what the
add put there.

The §3.4.2 rules encoded: CNAME exclusivity in both directions (excluding RRSIG,
NSEC and NSEC3, which RFC 4035 §2.5 permits beside a CNAME); the SOA serial rule;
duplicate-RDATA replacement, which is how an UPDATE changes a TTL; the apex SOA
and NS protections in both halves of §3.4.2.3; and §3.4.2.4's last-NS protection,
which asks what the deletion would *leave* rather than whether the RRset is
currently a singleton.

Changes the RFC requires be ignored are reported and logged at INFO, because
§3.4.2.5 signals NOERROR regardless.

> Where the prose and the pseudocode disagree, the prose wins. §3.4.2.2 ignores
> an SOA whose serial is "lower ... than or equal to" the current one; §3.4.2.7
> spells the same test as `zone.serial > rr.serial`, which *accepts* an equal
> serial.

### The serial

§3.6's automatic bump fires only when something changed.

For a signed zone the served serial is the file's plus a time term
(`zone_signer::signed_serial`). Because that term is added rather than `max`ed,
an UPDATE's `+1` survives signing as a `+1` in the served number.

### Persistence

The zone file is written before the client is told the update succeeded: the
re-signing timer reloads every zone from its file, so a change that lived only in
the zone map would be discarded within one re-signing interval.

An UPDATE is therefore a zone-file edit followed by the load path: read the zone
as the file has it, check §3.2 against that, apply, write atomically, sign,
install. §3.7's atomicity is one mutex held across the whole read-modify-write.

### Re-signing

A signed zone is re-signed incrementally, carrying forward every signature whose
RRset did not move (`zone_signer::sign_zone_incrementally`). Every RRSIG's
inception and expiration derive from the run's `signed_at`, so a full re-sign
would change every signature's RDATA and `ixfr::diff` would put all of them in
the delta.

The denial chain is still built in full, and the signatures that came out
byte-identical are carried forward. Inserting one name changes the denial record
at that name and at its predecessor, so no neighbour set is ever computed.

A signature is carried forward only when the RRset is identical as a *set*, at
least one signature existed, the signing keys are unchanged by key tag, and
nothing carried has already expired. Being near expiry is deliberately not a
condition.

---

## 3.8 Reload

Triggered by SIGHUP (Unix), by `rdnsctl reload`, or by the zone-maintenance timer
(which also re-signs; see `04-dnssec.md` §4.1).

All or nothing. `Reloading::load` reads every zone, signs every zone that has a
key, verifies every signature, and installs the new set only if the whole set
came through. A failure leaves the previously served zones in place and reports
why; `rdnsctl reload` exits 1 with the parse error.

1. Read and parse every zone on a blocking thread (`spawn_blocking`).
2. `plan_reload` diffs the new set against the old under the read lock.
3. Install under the write lock, briefly.
4. `withdraw_unvouched_zones` (§3.6).
5. `note_serials` updates the per-zone metric gauges; zones no longer present are
   forgotten, not frozen.
6. NOTIFY every zone whose serial moved forward (§3.5).

---

## 3.9 The control socket

`--control-socket <path>`, Unix only — `tokio` has no `UnixListener` on Windows,
so it is refused there at startup.

Created mode 0600; filesystem permissions are the authentication. There is no
control port, and these commands are not on `--metrics-listen`.

Protocol (`rdns/src/control.rs`): one command line in, a status line
(`+OK` / `-ERR`) and a body out, then close. Plain text, so
`printf 'status\n' | socat - UNIX-CONNECT:...` is a working client.

| command | does |
|---|---|
| `status` (default) | zones, serials, last transfer, uptime, counters |
| `reload` | a full reload, answering whether it worked; server-side bound 120 s |
| `dump <zone>` | the zone in presentation form |
| `version` | `rdnsd <version>` |
| `help`, empty | usage |

Request bound: `control::MAX_REQUEST` = 4096 bytes.

`rdnsctl` exit codes: 0 the command worked, 1 the server refused it, 2 we could
not ask.
