# 4. DNSSEC

`rdns/src/dnssec.rs` (crypto and RRset verification), `dnssec_denial.rs`
(NSEC/NSEC3 proofs, both directions), `dnssec_chain.rs` (chain of trust, trust
anchors), `dnssec_key.rs` (private keys), `zone_signer.rs` (signing),
`dnssec_answer.rs` (what a signed answer carries), `nsec_cache.rs` (RFC 8198),
`rfc5011.rs` (managed anchors).

---

## 4.1 Signing a zone

### Where signatures live

In memory, on load. The zone file on disk is never rewritten. `zone_writer` can
spell the signed form out as a debugging convenience.

### Keys

`--signing-key-dir <dir>` holds `.rdnskey` private keys, named
`K<owner>+<algorithm>+<tag>.rdnskey`. Every zone whose apex matches a key there
is signed as it loads; zones with no key are served unchanged.

`--generate-keys <zone>` writes a KSK and a ZSK into that directory, prints the
DS to give the parent, and exits. Algorithm from `--key-algorithm`. Two keys
because only the KSK is digested into the DS.

| algorithm | code | generate | sign | verify |
|---|---|---|---|---|
| RSA/SHA-1 (5), RSASHA1-NSEC3 (7) | 5, 7 | no | no | yes — RFC 8624 §3.1 NOT RECOMMENDED, accepted deliberately |
| RSA/SHA-256 | 8 | no | import only | yes |
| RSA/SHA-512 | 10 | no | import only | yes |
| ECDSA P-256/SHA-256 | 13 | yes (default) | yes | yes |
| ECDSA P-384/SHA-384 | 14 | yes | yes | yes |
| Ed25519 | 15 | yes | yes | yes |

`ring` does not generate RSA keys, which is why 8 and 10 are import-only.

DS digest types: 1 (SHA-1), 2 (SHA-256), 4 (SHA-384). The digest input is
`canonical owner name || DNSKEY RDATA`.

### What gets signed

Signed: every RRset the zone is authoritative for, plus the DNSKEY RRset, plus
the denial chain.

Not signed: a delegation's NS RRset (it is the child's data, RFC 4035 §2.2), and
glue below a cut. The only signed thing at a delegation point is the DS, plus the
denial record that lets the absence of a DS be proved.

A DNAME *is* signed, and its owner is chained like any other name: its bitmap
carries the DNAME bit, which RFC 6672 §5.3.2 makes load-bearing — a validator
checks it to tell a genuine NXDOMAIN below the owner from one that skipped the
redirection. The CNAME the answer path synthesizes from it is never signed
(§5.3.1); see §4.3.

Names *below* a DNAME owner are occluded and left out of the chain, exactly as
glue below a delegation is — RFC 2136 §7.18 names both, and RFC 6672 §2.4 points
at it. `zone.rs`'s loader refuses such a zone outright, so this covers one that
arrived by transfer or was built by UPDATE, which §5.2 has adding a DNAME over
existing names on purpose.

### Idempotence

`sign_zone` drops the signer's own previous output (RRSIG, NSEC, NSEC3,
NSEC3PARAM) before generating anything. DNSKEY records are not dropped — a key
published without its private half is how a rollover starts.

### Validity, spread and re-signing

| knob | value | where |
|---|---|---|
| validity | `--signature-validity` days, default 30 | `SigningPolicy::valid_for` |
| re-sign after | validity / 3 | `RESIGN_FRACTION` |
| expiry spread | validity / 5, pulled back from the end | `EXPIRY_JITTER_FRACTION` |

- The spread is deterministic, FNV-1a over `(lower-cased owner name, type)`.
  `DefaultHasher` cannot be used: its output is randomized per process.
- Expiry never goes past the requested validity. `expiry_for` subtracts and
  floors at `inception + 1`.

The re-signing timer also picks up a zone-file edit within one interval without a
SIGHUP. The derived global interval follows the shortest validity of any zone.

### The served SOA serial

```
served_serial = file_serial + (unix_seconds / 3600)      // wrapping, RFC 1982 §3.1
```

Re-signing is a new version of the zone as far as a secondary is concerned, and a
secondary decides whether to transfer by comparing serials.

`+` and not `max`: a date-style serial like `2026073001` is numerically larger
than any current Unix timestamp, so `max` would keep the file's number and never
bump. Hours rather than a finer unit keeps the term small (~495,000 today), and
hours since the *epoch* rather than a fraction of the validity means changing
`--signature-validity` cannot move the serial backwards.

The served serial and the file's serial are different numbers and cannot collide.

### Denial chains

| | NSEC | NSEC3 |
|---|---|---|
| flag | default | `--nsec3` |
| opt-out | — | `--nsec3-opt-out` (requires `--nsec3`) |
| salt | — | empty, per RFC 9276 §3.1 |
| iterations | — | 0, per RFC 9276 §3.1 |

The reason to choose NSEC3 is that NSEC lets anyone walk the zone one query at a
time.

Refused at signing time: a salt over 255 octets; iterations over
`MAX_NSEC3_ITERATIONS` (the RFC 9276 cap) — what we would refuse to validate, we
refuse to sign.

A denial record's bitmap lists every type present at the name it describes
(RFC 5155 §7.1, RFC 4034 §4.1.2), so the layout is taken after every mutation,
never before.

### `--require-signed`

Refuses to serve a zone that is unsigned, or whose signatures do not verify. Off
by default. Verification at load runs the zone's own signatures through
`verify_rrset`.

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

Only `Bogus` says the data must not be served as authentic. `Unsupported` means
no opinion either way. The same split runs one level down in `dnssec::verify`:
`Ok(false)` is a wrong signature, `Err` is no opinion, and a caller MUST NOT
treat `Err` as a forgery.

`RrsetProof` is per-RRset. [`ValidationState`](#44-validating-as-a-resolver) is
the per-answer verdict a resolver reaches after walking the chain, and its
`Insecure` — *provably* unsigned — is a stronger claim than
`RrsetProof::Unsigned`.

Canonicalization follows RFC 4034 §6: owner names down-cased, RDATA names
down-cased for the types §6.2 lists (`dnssec.rs:371` — NS, CNAME, PTR, SOA, MX,
RRSIG, NSEC), records sorted by canonical RDATA order, the RRSIG RDATA without
its signature field prepended.

Wildcard reconstruction: an RRSIG whose `labels` count is fewer than the owner's
was made at `*.<the last `labels` labels>` (RFC 4035 §5.3.2).

Time validity: `utils::is_time_expired(inception, expiration)` — RFC 4034 §3.1.5
serial-number arithmetic, not a plain comparison.

---

## 4.3 What a signed answer owes

`dnssec_answer.rs`. Three of the four shapes owe a proof rather than a signature.

| answer | owes |
|---|---|
| plain positive | the RRSIGs covering it |
| wildcard positive | those RRSIGs, re-owned onto the queried name, plus a denial that the queried name exists (RFC 4035 §3.1.3) |
| NODATA | the SOA's RRSIG, plus the denial record *at* the name whose bitmap lacks the type |
| NODATA through a wildcard | that record at the wildcard, plus a denial of the name actually asked for |
| NXDOMAIN | a denial of the name and of the wildcard that could have answered it (RFC 4035 §5.4) |
| referral | the DS with its signature, or the authenticated denial that there is one (RFC 4035 §3.1.4) |
| DNAME redirection | the DNAME's own RRSIG — and **nothing** for the synthesized CNAME (RFC 6672 §5.3.1) |

Every denial record travels with its own signature.

The unsigned synthesized CNAME is the design and not an omission: "the CNAME will
never be signed", because a server that signs offline cannot sign a record it
invents per query. "For a DNSSEC validator, verification of the DNAME RR and then
that the CNAME was properly synthesized is sufficient proof" (§5.3.1). A chain
mixing DNAME, CNAME and a final answer is as strong as its weakest link — AD only
if every step is secure (§5.3.3).

Nothing is added to an unsigned zone, whatever the client asked for. "Is this
zone signed" is tested as "does the apex publish a DNSKEY RRset", not "are there
any RRSIGs".

Duplicate denial records are sent once: the same NSEC often denies both a name
and the wildcard above it.

### NSEC3 specifics

- Chain parameters (salt, iterations) are read off the chain itself, from any
  NSEC3 record, not off NSEC3PARAM.
- The closest encloser is found by walking up and hashing, not by consulting the
  name index: under NSEC3 an empty non-terminal has an NSEC3 and no records of
  its own.
- Under opt-out, an insecure delegation has no NSEC3 of its own
  (RFC 5155 §7.2.9), so the no-DS proof is the closest-encloser pair.
- The proof reader treats an opt-out span as unjudgeable, not as proof.
- An NSEC3 with a hash algorithm other than 1 is dropped (RFC 5155 §8.1).
- Both NSEC3 proof loops skip a record they cannot hash and keep looking, rather
  than ending the search at the first one — §8.1's "responses containing *only*
  such NSEC3 RRs will generally be considered bogus" is about the whole set.

---

## 4.4 Validating as a resolver

`dnssec_chain.rs`, driven by `resolver::validate` when `--dnssec-validate` is on.

```rust
enum ValidationState { Secure, Insecure, Bogus(String), Indeterminate }
```

- `Secure` — a chain from a trust anchor to the answer, every link verified. AD
  is set on the reply.
- `Insecure` — a *proven* unsigned delegation: the parent's authenticated denial
  that a DS exists. The answer is served; AD is clear.
- `Bogus` — a signature that should verify and does not, or a stripped DS (a
  delegation claiming to be unsigned with no denial to back it). SERVFAIL, unless
  the client set CD.
- `Indeterminate` — no anchor covers this name.

A stripped DS is `Bogus`, never `Insecure`.

The negative proof is about the end of the CNAME chain, not the name asked about
(RFC 4035 §5.4), and "is this negative?" is not `answers.is_empty()`.

### Trust anchors

- Built in: the ICANN root KSK.
- `--trust-anchor <file>` — DS presentation format, read and never written.
- `--auto-trust-anchor <file>` — read and written (RFC 5011, `rfc5011.rs`): the
  resolver watches the zone's own signed DNSKEY RRset, adopts a new key after 30
  days of continuous publication, and drops one the zone revokes with a signature
  from that same key. Created from the anchors in force if it does not exist.

### RFC 8198 — aggressive use of validated denials

`nsec_cache.rs`. Validated NSEC/NSEC3 records are kept per zone (bounded by
`NSEC_CACHE_ZONES` = 1000 zones in `rdnsr`, and per-zone within that), and a
later query for a name inside a proven gap is answered from the cache without a
round trip. Holds validated material only, so it is empty unless
`--dnssec-validate` is on.

### Iteration and work caps

- NSEC3 iterations above the RFC 9276 cap: refused, at both signing and
  validation.
- A resolver's query budget (`Budget`) bounds the total work per resolution;
  exhausting it is `ResolveError::BudgetExhausted`.
