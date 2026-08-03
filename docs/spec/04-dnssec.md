# 4. DNSSEC

`rdns/src/dnssec.rs` (crypto and RRset verification), `dnssec_denial.rs`
(NSEC/NSEC3 proofs, both directions), `dnssec_chain.rs` (chain of trust,
trust anchors), `dnssec_key.rs` (private keys), `zone_signer.rs` (signing),
`dnssec_answer.rs` (what a signed *answer* carries), `nsec_cache.rs` (RFC 8198),
`rfc5011.rs` (managed anchors).

---

## 4.1 Signing a zone

### Where signatures live

**In memory, on load. The zone file on disk is never rewritten.** One decision,
three reasons: a signer that rewrites its input has to solve the "who owns this
file" problem the transfer sidecar deliberately stepped around, an editor and a
re-signing timer racing for one file is a way to lose a zone, and what a client
validates is what leaves the socket. `zone_writer` can spell the signed form out,
as a debugging convenience.

### Keys

`--signing-key-dir <dir>` holds `.rdnskey` private keys, named
`K<owner>+<algorithm>+<tag>.rdnskey`. Every zone whose apex
matches a key there is signed as it loads; zones with no key are served exactly
as they were.

`--generate-keys <zone>` writes a KSK and a ZSK into that directory, prints the
DS to give the parent, and exits. Algorithm from `--key-algorithm`.

| algorithm | code | generate | sign | verify |
|---|---|---|---|---|
| RSA/SHA-1 (5), RSASHA1-NSEC3 (7) | 5, 7 | no | no | **yes** — RFC 8624 §3.1 says NOT RECOMMENDED, but a long tail of zones is signed with it and refusing would mark them bogus rather than let their signatures speak |
| RSA/SHA-256 | 8 | no | import only | yes |
| RSA/SHA-512 | 10 | no | import only | yes |
| ECDSA P-256/SHA-256 | 13 | **yes (default)** | yes | yes |
| ECDSA P-384/SHA-384 | 14 | yes | yes | yes |
| Ed25519 | 15 | yes | yes | yes |

`ring` does not generate RSA keys, which is why 8 and 10 are import-only.

DS digest types: **1 (SHA-1), 2 (SHA-256), 4 (SHA-384)**. The digest input is
`canonical owner name || DNSKEY RDATA` — hashing the RDATA alone produces a value
matching nothing a real parent publishes and turns every secure delegation into a
failure.

### What gets signed, and what does not

Signed: every RRset the zone is **authoritative** for, plus the DNSKEY RRset,
plus the denial chain.

**Not signed**, and this is not an omission:

- **A delegation's NS RRset.** It is the child's data (RFC 4035 §2.2). Signing it
  is the classic signer bug: every validator ignores the signature, and the extra
  RRSIG turns up in the parent's NSEC bitmap as a type that is not there.
- **Glue below a cut.** It is not in the zone.

The only signed thing at a delegation point is the **DS**, plus the denial record
that exists precisely so the *absence* of a DS can be proved.

### Idempotence

`sign_zone` drops the signer's own previous output (RRSIG, NSEC, NSEC3,
NSEC3PARAM) before generating anything, so signing a signed zone produces a
freshly signed zone rather than one with two chains in it. **DNSKEY records are
not dropped** — a key published without its private half is how every rollover
starts, and deleting it would undo the operator's preparation.

### Validity, spread and re-signing

| knob | value | where |
|---|---|---|
| validity | `--signature-validity` days, default **30** | `SigningPolicy::valid_for` |
| re-sign after | validity / **3** | `RESIGN_FRACTION` |
| expiry spread | validity / **5**, pulled *back* from the end | `EXPIRY_JITTER_FRACTION` |

- **Do not give every RRSIG the same expiration.** They then all expire in the
  same second, turning "signatures lapsed" into "the entire zone SERVFAILs at
  every validator at once".
- **The spread is deterministic**, FNV-1a over `(lower-cased owner name, type)`.
  Random jitter would reshuffle the slope on every reload and no two servers
  holding the zone would agree about it. `DefaultHasher` cannot be used: its
  output is randomized per process.
- **Never spread past the requested validity.** 30 days means at most 30 days,
  never 35. `expiry_for` subtracts and floors at `inception + 1`.
- **Re-sign with slack**, at a third of the validity (BIND uses a quarter), so a
  run that fails, or a server down over one, does not expire anything.

The re-signing timer also picks up a zone-file edit within one interval without
a SIGHUP. A **derived global** interval follows the **shortest** validity of any
zone, because a seven-day zone among thirty-day ones is the one that expires if
the timer runs on the global number.

### The served SOA serial

```
served_serial = file_serial + (unix_seconds / 3600)      // wrapping, RFC 1982 §3.1
```

**Why a bump is needed at all.** Re-signing is a new version of the zone as far
as a secondary is concerned — new RRSIGs are new data — and a secondary decides
whether to transfer by comparing serials. Without a bump the replica keeps the
signatures it has and they expire underneath it: the same outage as never
re-signing, one hop downstream.

**Why `+` and not `max`.** PowerDNS's `INCEPTION-EPOCH` documents itself as
"requiring epoch-based backend serials" for exactly this reason: a date-style
serial like `2026073001` is numerically larger than any current Unix timestamp,
so a `max` would keep the file's number and never bump.

**Why hours.** The term stays small (~495,000 today) so it does not crowd a
date-style serial towards the 32-bit ceiling, and a re-sign every ten days is far
coarser than an hour. Hours since the *epoch* rather than a fraction of the
validity, so changing `--signature-validity` cannot move the serial backwards.

The served serial and the file's serial are **different numbers** and cannot
collide, which is what dissolves the "but the operator owns that number"
objection — the same way BIND's inline-signing serves a number that visibly
drifts from the file's.

### Denial chains

| | NSEC | NSEC3 |
|---|---|---|
| flag | default | `--nsec3` |
| opt-out | — | `--nsec3-opt-out` (requires `--nsec3`) |
| salt | — | **empty**, per RFC 9276 §3.1 |
| iterations | — | **0**, per RFC 9276 §3.1 |

Both salt and iterations were meant to cost an attacker something and only ever
cost the server and the validator. The remaining reason to choose NSEC3 is that
NSEC lets anyone walk the zone one query at a time — a disclosure question, not a
security one.

Refusals at signing time: a salt over 255 octets; iterations over
`MAX_NSEC3_ITERATIONS` (the RFC 9276 cap). **Refusing to sign what we would
refuse to validate is the point** — a zone signed above the cap would be a zone we
could not read ourselves.

**A denial record's bitmap must list every type present at the name it
describes** (RFC 5155 §7.1, RFC 4034 §4.1.2). This makes snapshot-then-mutate a
bug pattern: `Layout::of` was once taken before NSEC3PARAM was added, so the apex
NSEC3 denied a type that was there — which an aggressive-NSEC resolver would then
synthesize as a false NODATA for other clients out of its cache.

### `--require-signed`

Refuses to serve a zone that is unsigned, or whose signatures do not verify. Off
by default, which is the only sane default for a server that may hold a mix.
Turning it on is an operator assertion that every zone here is meant to be
signed — worth making, because a zone that silently loses its signatures
otherwise keeps answering as though nothing happened.

Verification at load runs the zone's own signatures through `verify_rrset` — the
same code that judges a real zone off the internet.

---

## 4.2 Verifying an RRset

`dnssec::verify_rrset(rrset, rrsigs, keys, zone, now) -> RrsetProof`

```rust
enum RrsetProof {
    Verified { wildcard: Option<String>, expires: u32 },
    Unsigned,             // no RRSIG covered this RRset at all
    Bogus(String),        // signatures were present and none verified
    Unsupported(String),  // signatures were present and we can read none of them
}
```

**Four variants, and the last three are the point.** `Unsigned` is the ordinary
case — most zones are unsigned — and is emphatically not a signature that failed.
`Unsupported` is "signatures were present but every one used an algorithm or key
we cannot read", so we have **no opinion either way**. Only `Bogus` says the data
must not be served as authentic.

The same split runs one level down, in `dnssec::verify`: **`Ok(false)` means the
signature is genuinely wrong; an `Err` means we could not form an opinion** — an
algorithm we do not implement, or a key whose bytes do not fit its algorithm —
**and a caller MUST NOT treat that as a forgery.**

`RrsetProof` is per-RRset. [`ValidationState`](#44-validating-as-a-resolver) is
the per-answer verdict a resolver reaches after walking the chain, and its
`Insecure` — *provably* unsigned — is a different and stronger claim than
`RrsetProof::Unsigned`.

Canonicalization follows RFC 4034 §6: owner names down-cased, RDATA names
down-cased for the types §6.2 lists (`dnssec.rs:371` — NS, CNAME, PTR, SOA, MX,
RRSIG, NSEC), records sorted by canonical RDATA order, the RRSIG RDATA without
its signature field prepended.

Wildcard reconstruction: an RRSIG whose `labels` count is fewer than the owner's
says the signature was made at `*.<the last `labels` labels>` (RFC 4035 §5.3.2),
and that is how a wildcard answer is recognised as one rather than as a forgery.

Time validity: `utils::is_time_expired(inception, expiration)` — RFC 4034 §3.1.5
serial-number arithmetic, not a plain comparison.

---

## 4.3 What a signed *answer* owes

`dnssec_answer.rs`. **Nothing here is optional to a validator.** Three of the
four shapes owe a *proof* rather than a signature.

| answer | owes |
|---|---|
| plain positive | the RRSIGs covering it |
| **wildcard positive** | those RRSIGs, re-owned onto the queried name, **plus a denial that the queried name exists** (RFC 4035 §3.1.3) |
| **NODATA** | the SOA's RRSIG, plus the denial record *at* the name whose bitmap lacks the type |
| **NODATA through a wildcard** | that record at the **wildcard**, plus a denial of the name actually asked for |
| **NXDOMAIN** | a denial of the name **and** of the wildcard that could have answered it (RFC 4035 §5.4) |
| **referral** | the DS with its signature, **or** the authenticated denial that there is one (RFC 4035 §3.1.4) |

Why each matters:

- Without the wildcard denial, one captured wildcard answer is a valid answer for
  **every** name that wildcard reaches.
- Without the NXDOMAIN wildcard denial, a validator accepts an NXDOMAIN for a
  name a wildcard answers.
- A referral carrying no DS and no denial is indistinguishable from one an
  attacker stripped the DS out of — the downgrade attack DNSSEC exists to stop.

**Every denial record travels with its own signature.** An unsigned NSEC in the
authority section is a record an attacker could have written.

**Nothing is added to an unsigned zone**, whatever the client asked for. DO says
the client can *understand* DNSSEC, not that the zone owes it anything. "Is this
zone signed" is tested as "does the apex publish a DNSKEY RRset", not "are there
any RRSIGs": a zone with signatures but no published key cannot be validated by
anyone, so serving its signatures turns an insecure answer into a bogus one.

### NSEC3 specifics

- Chain parameters (salt, iterations) are read **off the chain itself**, from any
  NSEC3 record, not off NSEC3PARAM. NSEC3PARAM tells a *server* which chain to
  use mid-rollover between two of them (RFC 5155 §4.1), and this server has one
  chain; a stale NSEC3PARAM would make every denial hash to something no record
  matches.
- The closest encloser is found by **walking up and hashing**, not by consulting
  the name index: under NSEC3 an empty non-terminal has an NSEC3 and no records
  of its own, so it is invisible to a lookup by name and stopping short of it
  produces a proof about the wrong encloser.
- Under **opt-out**, an insecure delegation has no NSEC3 of its own
  (RFC 5155 §7.2.9), so the no-DS proof is the closest-encloser pair instead.
- The proof reader treats an **opt-out span as unjudgeable**, not as proof:
  "this name does not exist" weakens to "does not exist, or is an insecure
  delegation I did not list".
- **An NSEC3 with a hash algorithm other than 1 is dropped**, per RFC 5155 §8.1's
  MUST-ignore. IANA reserves 0 and leaves 2–255 unassigned, so 1 is all there is.
- Both NSEC3 proof loops **skip** a record they cannot hash and keep looking,
  rather than ending the search at the first one. §8.1's "responses containing
  **only** such NSEC3 RRs will generally be considered bogus" is a statement about
  the whole set; ending at the first would flip a proof on record ordering alone.

Duplicate suppression: the same NSEC often denies two things at once (a name and
the wildcard above it are frequently in the same gap). It is sent once — a
validator de-duplicates, and the second copy is bytes on an amplification path.

---

## 4.4 Validating as a resolver

`dnssec_chain.rs`, driven by `resolver::validate` when `--dnssec-validate` is on.

```rust
enum ValidationState { Secure, Insecure, Bogus(String), Indeterminate }
```

- **Secure** — a chain from a trust anchor to the answer, every link verified.
  AD is set on the reply.
- **Insecure** — a *proven* unsigned delegation: the parent's authenticated
  denial that a DS exists. The answer is served; AD is clear.
- **Bogus** — a signature that should verify and does not, or a **stripped DS**
  (a delegation claiming to be unsigned with no denial to back it). SERVFAIL,
  unless the client set CD.
- **Indeterminate** — no anchor covers this name.

`Bogus` and `Insecure` must not be confused: treating a stripped DS as insecure
is the downgrade.

A resolver-side answer's negative proof is about **the end of the CNAME chain**,
not the name asked about (RFC 4035 §5.4). "Is this negative?" is not
`answers.is_empty()`: a chain ending without the queried type is a negative answer
with a non-empty answer section.

### Trust anchors

- Built in: the ICANN root KSK.
- `--trust-anchor <file>` — DS presentation format, **read and never written**.
  The operator's decision; a key roll means editing it.
- `--auto-trust-anchor <file>` — **read and written** (RFC 5011, `rfc5011.rs`):
  the resolver watches the zone's own signed DNSKEY RRset, adopts a new key once
  it has been published continuously for **30 days**, and drops one the zone
  revokes with a signature from that same key. Created from the anchors in force
  if it does not exist, so pointing at a new path is enough to start.

### RFC 8198 — aggressive use of validated denials

`nsec_cache.rs`. Validated NSEC/NSEC3 records are kept per zone (bounded by
`NSEC_CACHE_ZONES` = 1000 zones in `rdnsr`, and per-zone within that), and a
later query for a name **inside a proven gap** is answered from the cache without
a round trip. One zone's NSEC chain answers for every non-existent name in it,
which is what covers the tail of a random-name flood.

Holds validated material only, so it is empty unless `--dnssec-validate` is on —
which is why the ordinary negative cache is not redundant with it.

### Iteration and work caps

- NSEC3 iterations above the RFC 9276 cap: refused, at both signing and
  validation.
- A resolver's query budget (`Budget`) bounds the total work per resolution;
  exhausting it is `ResolveError::BudgetExhausted`, which is an operational
  signal (the NXNSAttack defence firing) rather than a lookup failure.
