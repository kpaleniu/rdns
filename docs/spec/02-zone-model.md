# 2. Zones: file syntax, storage, and lookup

`rdns/src/zone.rs`, `rdns/src/zone_writer.rs`.

---

## 2.1 Zone-file syntax (RFC 1035 §5)

### Directives

| directive | supported | behaviour |
|---|---|---|
| `$ORIGIN <name>` | yes | applies to the lines below it only |
| `$TTL <seconds>` | yes | the default TTL for records that omit one |
| `$INCLUDE <path> [origin]` | yes | resolved relative to the including file's directory; nesting capped at `MAX_INCLUDE_DEPTH` = 8 |
| `$GENERATE` | no | BIND extension, not RFC |

### Line structure

- A logical line may span physical lines inside `( ... )` (`logical_lines`,
  `zone.rs:842`).
- `;` starts a comment, except inside a quoted string.
- An indented line with no owner name inherits the previous line's owner. A
  leading-whitespace line with no previous owner is an error.
- `@` and the empty owner name mean the current origin.
- An owner name not ending in `.` is relative to the origin in force at that
  line.

### Record fields

`[owner] [ttl] [class] TYPE rdata...`, with TTL and class each optional and
order-independent between them. Types readable in presentation form:

A, AAAA, NS, CNAME, MX, TXT, PTR, SOA, DNSKEY, DS, RRSIG, NSEC, NSEC3.

Anything else MUST be written in RFC 3597 `\#` generic form
(`parse_generic_rdata`, `zone.rs:789`), or the line is an error. Type mnemonics
also accept `TYPEnnn` (`utils::record_type_name_to_code`), and the zone writer
emits that form for types it has no mnemonic for.

TXT `<character-string>`s are split on quotes, not on whitespace, so `"a b" "c"`
is two strings and not three.

### What the parser refuses

Refusals at load, not warnings:

1. A record in a class other than IN.
2. A CNAME sharing its owner name with any other type
   (`check_cname_exclusivity`, `zone.rs:1033`), per RFC 1034 §3.6.2.
3. Malformed RDATA for a known type, an unsupported type name in non-generic
   form, an out-of-range field, an unparseable `$TTL`.

A file that fails any of these produces a `ZoneError` carrying the line number.

### All-or-nothing loading

`rdnsd` refuses to start if any zone in `--zone-dir` fails to parse.
`--allow-partial-load` opts into serving the rest.

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

`origin` and `records` are private, because the index is derived from both.
`add_record` and `set_origin` are the only ways to change either, and both
maintain the index.

The index is keyed on the name, not on (name, type), so that "does this name
exist at all" — which decides NXDOMAIN against NODATA — is answerable without
probing 65535 types. The chains are ordered maps because a denial asks a range
question. `non_terminals` is separate from `index` because those names have no
records of their own (RFC 4592 §2.2.2).

### Lookup key

`Zone::lookup_key(name)` = absolutize against the origin, then ASCII-fold.
Returns `Cow`, borrowing when the name needs neither step.

---

## 2.3 Name resolution inside a zone

### `Zone::name_kind(name) -> NameKind`

| variant | condition | answer shape |
|---|---|---|
| `Exact` | the index holds this key | records, or NODATA |
| `EmptyNonTerminal` | in `non_terminals` | always NODATA — the name exists (RFC 4592 §2.2.2) |
| `Wildcard(w)` | not present, and `w = *.<closest encloser>` is | synthesized answer |
| `NotFound` | none of the above | NXDOMAIN |

The wildcard search is a closest-encloser walk:

1. Walk up from the queried name to the first ancestor that is a node of the zone
   (has records or is a non-terminal).
2. If a delegation sits at or above that encloser, the answer is `NotFound`
   (RFC 4592 §2.2.1) and the caller owes a referral.
3. Otherwise the only wildcard that may answer is `*.<that encloser>`
   (RFC 4592 §3.3.1); `*.<grandparent>` is not tried (§4.4).

Synthesis reaches any depth (RFC 4592 §3.3.2), and an existing name — empty
non-terminals included — ends the search.

### `Zone::query(name, qtype) -> Vec<&ZoneRecord>`

The wildcard is consulted only when `name_kind` says `Wildcard`. An existing
name, or an empty non-terminal, shadows the wildcard entirely, including for
types it does not carry. Type selection is `Qtype::matches`.

### `Zone::delegation_for(name) -> Option<String>`

The deepest ancestor-or-self other than the apex carrying an NS RRset
(RFC 1034 §4.2.1). The apex is excluded because its NS RRset is this zone's own.

### Helpers

- `Zone::holds_name(name)` — records at exactly this name, no wildcard, which is
  what the denial path needs (RFC 4035 §3.1.3).
- `Zone::name_exists(name)` — `name_kind != NotFound`.
- `Zone::serial()` — the apex SOA's serial, as a `Serial`.
- `Zone::nsec_covering(name)` / `nsec3_covering(hash)` — the record whose span
  contains the argument, exclusive at the low end. When nothing sorts before it,
  the last record in the chain is returned, because the chain is a loop
  (RFC 4034 §4.1.1).

---

## 2.4 Writing a zone back out

`rdns/src/zone_writer.rs`. Used by `rdnsd`'s secondary role (to persist a
transferred zone) and by `rdnsctl dump`.

- Every type is written in a form `parse_zone_file` reads back; unknown types go
  out as RFC 3597 `\#`.
- The SOA block is written multi-line inside `( )` with aligned fields.
- The zone file on disk is never rewritten by the signer; see `04-dnssec.md`
  §4.1.

---

## 2.5 Known limits

| limit | value | note |
|---|---|---|
| classes | IN only | non-IN records refused at load; non-IN questions REFUSED |
| `$GENERATE` | unsupported | |
| escaped labels | unsupported | see `01-wire-format.md` §1.1 |
| zone size | memory-bound | the whole zone is resident; there is no on-disk format |
| CNAME hops within a zone | 16 | `MAX_CNAME_HOPS`, `rdnsd/src/main.rs:689` |
