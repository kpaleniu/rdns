# 2. Zones: file syntax, storage, and lookup

`rdns/src/zone.rs`, `rdns/src/zone_writer.rs`.

---

## 2.1 Zone-file syntax (RFC 1035 §5)

### Directives

| directive | supported | behaviour |
|---|---|---|
| `$ORIGIN <name>` | yes | applies to the lines **below** it only |
| `$TTL <seconds>` | yes | the default TTL for records that omit one |
| `$INCLUDE <path> [origin]` | yes | resolved relative to the including file's directory; nesting capped at `MAX_INCLUDE_DEPTH` = **8**, because a file that includes itself is a loop and the only way to notice is to stop counting |
| `$GENERATE` | **no** | not implemented (BIND extension, not RFC) |

### Line structure

- A logical line may span physical lines inside `( ... )` (`logical_lines`,
  `zone.rs:842`).
- `;` starts a comment, **except inside a quoted string**.
- An indented line with no owner name inherits the previous line's owner. A
  leading-whitespace line with no previous owner is an error.
- `@` and the empty owner name mean the current origin.
- An owner name not ending in `.` is relative to the origin in force at that
  line.

### Record fields

`[owner] [ttl] [class] TYPE rdata...`, with TTL and class each optional and
order-independent between them. Types readable in presentation form:

**A, AAAA, NS, CNAME, MX, TXT, PTR, SOA, DNSKEY, DS, RRSIG, NSEC, NSEC3.**

Anything else MUST be written in RFC 3597 `\#` generic form
(`parse_generic_rdata`, `zone.rs:789`), or the line is an error. Type mnemonics
also accept `TYPEnnn` (`utils::record_type_name_to_code`), and the zone writer
emits that form for types it has no mnemonic for — so a zone written out is a
zone this parser reads back.

TXT `<character-string>`s are split **on quotes, not on whitespace**, so
`"a b" "c"` is two strings and not three.

### What the parser refuses

These are refusals at load, not warnings:

1. **A record in a class other than IN.** This is what makes the class-blind zone
   index correct rather than merely untested; see §2.3.
2. **A CNAME sharing its owner name with any other type** (`check_cname_exclusivity`,
   `zone.rs:1033`), per RFC 1034 §3.6.2.
3. Malformed RDATA for a known type, an unsupported type name in
   non-generic form, an out-of-range field, an unparseable `$TTL`.

A file that fails any of these produces a `ZoneError` carrying the line number.

### All-or-nothing loading

`rdnsd` refuses to start if **any** zone in `--zone-dir` fails to parse. The
`--allow-partial-load` flag opts into serving the rest, and exists because a
secondary holding 40 zones would rather serve 39 than none — but it is a
decision, not the default. The default is the safe one: one typo plus a deploy
SIGHUP would otherwise be a lame delegation with every dashboard green.

---

## 2.2 The in-memory zone

```rust
pub struct Zone {
    origin: String,                             // absolute
    records: Vec<ZoneRecord>,                   // load order
    index: HashMap<NameKeyBuf, Vec<usize>>,     // owner name -> positions
    nsec_chain:  BTreeMap<Vec<u8>, usize>,      // canonical sort key -> position
    nsec3_chain: BTreeMap<Vec<u8>, usize>,      // owner hash -> position
    non_terminals: HashSet<NameKeyBuf>,         // names that exist because a descendant does
}
```

`origin` and `records` are **private**, because the index is derived from both.
`add_record` and `set_origin` are the only ways to change either, and both
maintain the index.

**Keyed on the name, not on (name, type).** A server needs two questions
answered and the second one is what tells NXDOMAIN from NODATA: "which records of
this type are at this name" and "does this name exist at all". A (name, type)
map cannot answer the second without probing 65535 types.

**The chains are ordered maps**, because a denial asks a *range* question — which
record's span contains this name — and a hash map cannot answer it without
scanning.

**`non_terminals` is a separate set** rather than folded into `index`, because a
zone holding only `deep.a.b.example.com.` has records at one name and four names
that exist (RFC 4592 §2.2.2), and the denial path needs the literal question too.

### Lookup key

`Zone::lookup_key(name)` = absolutize against the origin, then ASCII-fold. It
returns `Cow` and borrows when the name needs neither step — which is every name
that arrived on the wire from a client that does not use 0x20 encoding.

---

## 2.3 Name resolution inside a zone

### `Zone::name_kind(name) -> NameKind`

| variant | condition | answer shape |
|---|---|---|
| `Exact` | the index holds this key | records, or NODATA |
| `EmptyNonTerminal` | in `non_terminals` | always NODATA — the name exists (RFC 4592 §2.2.2) |
| `Wildcard(w)` | not present, and `w = *.<closest encloser>` is | synthesized answer |
| `NotFound` | none of the above | NXDOMAIN |

The wildcard search is a **closest-encloser walk**, not a single lookup:

1. Walk up from the queried name to the first ancestor that is a node of the zone
   (has records *or* is a non-terminal).
2. If a **delegation** sits at or above that encloser, the answer is `NotFound` —
   a wildcard below a zone cut is the child's data (RFC 4592 §2.2.1), and the
   caller owes a referral.
3. Otherwise the **only** wildcard that may answer is `*.<that encloser>`
   (RFC 4592 §3.3.1). Going on to try `*.<grandparent>` would answer for a name
   whose parent exists, which §4.4 forbids.

Synthesis therefore reaches **any depth** — RFC 4592 §3.3.2's worked example
answers `_telnet._tcp.host1.example.` from `*.example.`, two labels down — and an
existing name, empty non-terminals included, ends the search.

### `Zone::query(name, qtype) -> Vec<&ZoneRecord>`

The wildcard is consulted **only** when `name_kind` says `Wildcard`. An existing
name shadows the wildcard entirely, including for types it does not carry, and so
does an empty non-terminal. Type selection is `Qtype::matches`, so ANY behaves as
`01-wire-format.md` §1.2 specifies.

### `Zone::delegation_for(name) -> Option<String>`

The **deepest** ancestor-or-self other than the apex carrying an NS RRset
(RFC 1034 §4.2.1). The apex is excluded because its NS RRset is this zone's own,
not a cut.

### Helpers

- `Zone::holds_name(name)` — records at exactly this name, no wildcard. The
  denial path needs this, because a name that exists only through a wildcard is
  precisely the name a wildcard answer must prove does *not* exist
  (RFC 4035 §3.1.3).
- `Zone::name_exists(name)` — `name_kind != NotFound`.
- `Zone::serial()` — the apex SOA's serial, as a `Serial`.
- `Zone::nsec_covering(name)` / `nsec3_covering(hash)` — the record whose span
  contains the argument, **exclusive at the low end** (a record sitting *at* the
  name proves the opposite). When nothing sorts before it, the last record in the
  chain is returned, because the chain is a loop (RFC 4034 §4.1.1).

---

## 2.4 Writing a zone back out

`rdns/src/zone_writer.rs`. Used by `rdnsd`'s secondary role (to persist a
transferred zone) and by `rdnsctl dump`.

- Every type is written in a form `parse_zone_file` reads back; unknown types
  go out as RFC 3597 `\#`.
- The SOA block is written multi-line inside `( )` with aligned fields.
- **The zone file on disk is never rewritten by the signer.** Signatures live in
  memory only; see `04-dnssec.md` §4.1.

---

## 2.5 Known limits

| limit | value | note |
|---|---|---|
| classes | IN only | non-IN records refused at load; non-IN questions REFUSED |
| `$GENERATE` | unsupported | |
| escaped labels | unsupported | see `01-wire-format.md` §1.1 |
| zone size | memory-bound | the whole zone is resident; there is no on-disk format |
| CNAME hops within a zone | 16 | `MAX_CNAME_HOPS`, `rdnsd/src/main.rs:689` |
