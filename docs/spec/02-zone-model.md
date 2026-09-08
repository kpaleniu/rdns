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

A, AAAA, NS, CNAME, DNAME, MX, TXT, PTR, SOA, SVCB, HTTPS, DNSKEY, DS, RRSIG,
NSEC, NSEC3.

Anything else MUST be written in RFC 3597 `\#` generic form
(`parse_generic_rdata`, `zone.rs:789`), or the line is an error. Type mnemonics
also accept `TYPEnnn` (`utils::record_type_name_to_code`), and the zone writer
emits that form for types it has no mnemonic for.

TXT `<character-string>`s are split on quotes, not on whitespace, so `"a b" "c"`
is two strings and not three.

### Escapes

RFC 1035 §5.1's escapes are resolved by the value that needs them
(`utils::char_string_decode`), not by the tokenizer, which keeps the backslash
so that `\DDD` still means something by the time a value sees it. `\X` is a
literal `X`; `\DDD` is one octet and the digit form is exactly three digits.

This reaches TXT and SVCB parameter values, and — since #36 — owner names and
name-valued RDATA as well, through `Name::from_presentation`. `a\.b IN A ...` is
one label holding a dot, and a CNAME target may spell one the same way.

~~It does **not** reach owner names or name-valued RDATA: those refuse a `\`
outright (`TODO.md` #13e), so the two octets with no faithful spelling in a
stored name — `.` and `\` — cannot get in.~~ True until #35 and #36, and left
standing because it is what the arithmetic below still assumed afterwards.
Before the decoder existed the tokenizer ate a backslash inside quotes, so
`"a\.b"` silently became two labels while the unquoted `a\.b` was refused.

The consequence is that presentation text no longer splits on `.`: a name's
labels are `utils::presentation_labels`, and `label_count`, `suffix_labels`,
`parent_name` and `is_at_or_under` are built on it. Four places had counted dots
instead, and the validator read a plain signed answer at such a name as expanded
from a wildcard that does not exist — `TODO.md` #37a.

### SVCB and HTTPS

`SvcPriority TargetName [key=value ...]` (RFC 9460 §2.1), with the parameter
shapes of §7. Written in any order; the wire form is sorted, because §2.2's
increasing-key rule is a canonical form and carries no information. A repeated
key is refused — two values with no rule for choosing between them.

The *spelling* picks the value format, not the number: `alpn=h2,h3` is a
comma-separated list, and `key1="\002h2"` is the same key written opaquely with
its value as raw octets. §7.1.1 depends on that distinction, since it offers the
opaque form as the way to write an ALPN id containing `,` or `\` — which this
parser refuses in the list form, as Appendix A.1 explicitly allows.

The writer never fails: a value that does not fit its key's shape — an
`ipv4hint` off the wire whose length is not a multiple of four — is written in
the `keyNNNNN` opaque form, which says the same octets and reads back the same.

### What the parser refuses

Refusals at load, not warnings:

1. A record in a class other than IN.
2. A CNAME sharing its owner name with any other type
   (`check_cname_exclusivity`), per RFC 1034 §3.6.2.
3. The four DNAME shapes RFC 6672 says a server should not load
   (`check_dname_rules`): two DNAMEs at one name and any record below a DNAME
   owner (§2.4), an NS RRset beside a DNAME below the apex (§2.3), and a
   wildcard DNAME (§3.3). The RFC hedges on all four — "ought to refuse" and
   "MAY refuse" — and each is refused here, because a name below a DNAME is
   occluded (RFC 2136 §7.18) whatever the file says. §2.4's fifth rule, a CNAME
   at a DNAME's owner, is rule 2 above. A DNAME at the *apex*, beside the
   customary SOA and NS, is legal (§2.3) and loads.
4. An AliasMode SVCB or HTTPS record (priority 0) carrying SvcParams.
   RFC 9460 §2.4.2 says recipients "MUST ignore any SvcParams that are present"
   and a parser "MAY emit a warning"; refused instead, because a parameter that
   is ignored is a setting the operator believes is in force and is not.
5. Malformed RDATA for a known type, an unsupported type name in non-generic
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
| redirections within a zone | 16 | CNAME and DNAME share the ceiling, because RFC 6672 §2.2 says they chain together: `MAX_REDIRECTS`, `rdnsd/src/answer.rs` |
