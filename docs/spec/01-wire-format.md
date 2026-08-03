# 1. Wire format

Everything in this file is implemented in `rdns/src/lib.rs`, `rdns/src/dname.rs`,
`rdns/src/compression.rs`, `rdns/src/record_data.rs` and `rdns/src/tsig.rs`.

---

## 1.1 Domain names

### Representation

A name is a Rust `String` in **presentation form**: labels separated by `.`, and
absolute names carry a trailing `.`. There is no label-vector or wire-byte
representation anywhere in the library; `dname.rs` documents this as a settled
decision rather than an accident.

Two consequences follow, and both are load-bearing:

- **A label containing `.` or `\` is refused, not escaped.** `dname.rs:75`
  (`unrepresentable_octet`) rejects both at the decode boundary and at
  `write_label`. The decode arm returns `WireError::Unsupported`.
  - The `.` case is refused because the presentation form would otherwise stop
    being injective — `a.b` as one label and `a`+`b` as two would be the same
    `String`, which would make `is_at_or_under("evil.com.", "com.")` answer true
    for a sibling of `com.`
  - The `\` case is refused because a name holding one cannot be written into a
    zone file that this reader reads back as the same name.
- **A label that is not valid UTF-8 is refused** (`dname.rs:143`), with
  `WireError::Malformed`. RFC 2181 §11 permits any binary string in a label, so
  this is a deviation. See `07-rfc-conformance.md` D-1.

### Limits enforced

| limit | value | where | RFC |
|---|---|---|---|
| label length | 63 octets | `write_label`, `Label::try_from_bytes` | 1035 §2.3.4 |
| name length, encoded | 255 octets | `UnpackedDName::new` (parse) and the encode path | 1035 §2.3.4 |
| empty label | refused | `write_label` | 1035 §3.1 |
| label syntax (LDH) | **not** enforced | `dname.rs:235` | 2181 §11 — deliberately not; see the comment |

The 255-octet limit counts each label's length octet and the terminating zero,
and is checked on **both** directions through **one** helper,
`dname::check_name_len` (`dname.rs:466`) — a name that arrived over the limit is a
parse error, and a name built in memory over the limit cannot be encoded. One
helper rather than two comparisons, because "two doors comparing the same limit by
different arithmetic is how the copies start".

### Compression (RFC 1035 §4.1.4)

**Decoding** (`DNameUnpacker::unpack_internal`, `dname.rs:295`):

- A pointer's 14-bit offset MUST be within the message, or the parse fails.
- Every pointer after the first in a chain MUST target a **strictly lower**
  offset than the previous one. A strictly decreasing sequence cannot repeat, so
  cycles are unreachable rather than detected — there is no visited-set.
- **The first hop is unconstrained** and may jump forward. This is deliberate
  and documented: a name is parsed from a suffix slice that does not know its own
  offset, so there is no start offset to compare against. Termination is
  unaffected.
- Pointer nesting is capped at 50 hops (`MAX_DEPTH`). This bounds work, not
  correctness.
- Extended label types (RFC 2673 binary labels `0x41`, and `0x7f`) return
  `WireError::Unsupported`, which the daemons answer NOTIMP for. Any other
  extended type is `Malformed` (FORMERR).

**Encoding** (`compression.rs`): owner names are compressed against everything
already written. RDATA is stored uncompressed and wire-ready and copied
verbatim, except for the record types whose embedded names may legally be
compressed, which `NameCompressor::write_rdata` handles.

### Case folding

ASCII only (RFC 4343), everywhere. `utils::ascii_lowered`,
`utils::ascii_lowered_cow`, `utils::names_equal`, `utils::absolute_lowered`.
`str::to_lowercase` MUST NOT be used on a name: it folds U+212A KELVIN SIGN onto
`k` and merges two names that differ on the wire.

`utils::NameKeyBuf` is the only type a name may be a map key as; its single
constructor folds.

---

## 1.2 The message

### `DnsMessage`

```
id: u16
response, authoritive, truncation, recursion, recursion_ok, ad, cd: bool
opcode: OpCode
rcode: ResponseCode          // 12-bit
queries: Vec<QuerySection>
answers, authorities, additionals: Vec<ResourceRecord>
edns: Option<Edns>           // NOT a member of `additionals`
```

**The OPT record is a field, not an additional record.** This makes two OPT
records in one message unspellable, which is what RFC 6891 §6.1.1's MUST-FORMERR
requires; the parser rejects a second OPT with `WireError::Malformed`
(`lib.rs:1716`). ARCOUNT is computed as `additionals.len() + edns.is_some()`.

### Header parsing

- A packet shorter than 12 octets is `Truncated`.
- OPCODE is `hi >> 3` masked to 4 bits. **Total**: every four-bit value maps to
  an `OpCode`, with `OpCode::Other(u8)` carrying the ones this implementation has
  no name for. `from_u8`/`to_u8` are exact inverses over the whole range, so an
  echoed opcode cannot change (RFC 1035 §4.1.1).
- RCODE is reassembled to 12 bits: the low 4 from the header, the high 8 from the
  OPT flags word when a message carries one (RFC 6891 §6.1.3).
  `ResponseCode::Other(u16)` carries unknown codes; `from_u16`/`to_u16` are
  inverses. An unrecognised failure code MUST NOT be relayed as NOERROR.

### Type and class spaces

Four newtypes, and the asymmetry between them is the design:

| type | meaning | conversions |
|---|---|---|
| `Rtype(u16)` | a record's TYPE | `Rtype -> Qtype` exists; the reverse does not |
| `Qtype(u16)` | a question's QTYPE | compare only via `Qtype::matches` / `Qtype::is` |
| `Class(u16)` | a record's CLASS | `Class -> QueryClass` exists; the reverse does not |
| `QueryClass` | a question's QCLASS | `matches` / `is` |

- `Qtype::matches(rtype)` is **the only** comparison of a question's type against
  stored data. `Qtype::ANY` matches every type **except** RRSIG, NSEC and NSEC3 —
  those are not answer-section data unless DO asked for them (RFC 4035 §3.1.1),
  and including them would make an empty non-terminal in an NSEC-signed zone look
  like a name with data.
- `Rtype::is_meta()` is true for ANY (255), AXFR (252) and IXFR (251) —
  values that appear in a TYPE field (RFC 2136 §2.4/§2.5) but that no stored
  record can have.
- `Class::is_meta()` is true for NONE (254) and ANY (255).
- `QueryClass::matches(class)` treats QCLASS ANY as matching every class
  (RFC 1035 §3.2.5).

### TTL

`Ttl(u32)`. `Ttl::from_wire(i32)` clamps a negative wire value to zero
(RFC 2181 §8) and is **the only** place the sign of the field is considered. An
OPT record's TTL field never goes through it: it is a flags word, read raw as
`u32` in `Additional::try_from_bytes`.

### Serial

`Serial(u32)`, with **no `PartialOrd` and no `Ord`**. `Serial::is_newer_than`
implements RFC 1982 §3.2: `forward = self.wrapping_sub(other); forward != 0 &&
forward < 2^31`. Equal serials are not newer. The undefined case (two serials
exactly half the space apart) answers `false` in both directions, which is why
there is no total order to derive.

`Serial::wrapping_add` is the defined addition in the sequence space.

### RDATA storage

`RecordData` (`record_data.rs`) holds `(Rtype, Box<[u8]>)` with **private
fields** in a one-struct module, so a value can only be built through a checking
constructor. `RecordData::parse()` produces a typed `ParsedRecord` on demand;
the parsed form is never stored.

**RDLENGTH = 0 is legal and parses** to `ParsedRecord::Unknown(rtype)`
(`lib.rs:581`). RFC 2136 §2.4.1/§2.4.2/§2.5.2/§2.5.3 spell prerequisites and
RRset deletions exactly that way, and rejecting it made every legal UPDATE
FORMERR at the wire layer. The cost is that an answer holding, say, an A with
RDLENGTH 0 parses rather than failing the whole message; RFC 3597 §5 already
requires carrying uninterpretable RDATA.

Typed record types: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, DNSKEY, RRSIG, DS,
NSEC, NSEC3. Everything else is `Unknown(Rtype)` with bytes preserved verbatim.

**TXT is `Vec<Vec<u8>>`** — a sequence of `<character-string>`s (RFC 1035
§3.3.14), each at most 255 octets, stored as bytes rather than `String`. A TXT
record holding two strings is a different record from one holding them joined.
Encoding a TXT with zero strings is an error.

**RRSIG field order on the wire is expiration then inception** (RFC 4034 §3.1),
and the encoder and decoder agree.

### Length checks

Every length that came off the wire is checked before use:
`read_be!` checks its own bytes; `Label::try_from_bytes` checks before slicing;
`Edns::walk_options` checks each TLV; and `read_record_parts` checks RDLENGTH
against the remaining message before `split_at` (`lib.rs:1548`).

---

## 1.3 Serialization

`DnsMessage::to_bytes(&mut [u8]) -> Result<usize>` writes into a caller-owned
buffer through `write_bytes`, which refuses to write past the end rather than
truncating silently.

- RCODE above `0xfff` is an error.
- RCODE above `0xf` with no OPT record is an error — there is nowhere to put the
  high bits.
- RDLENGTH, ARCOUNT and OPT RDLENGTH that do not fit `u16` are `TooLong` errors.
- The OPT record is written **last** in the additional section, so that
  `tsig::append_tsig` (which appends to the finished bytes) leaves the TSIG final
  as RFC 8945 §5.1 requires.

### Truncation

`to_bytes_within(max_len)` / `to_bytes_within_buf(max_len, &mut Vec<u8>)`:

1. Serialize into a scratch buffer of exactly `max_len` bytes.
2. On success within the limit, return those bytes.
3. On `WireError::Truncated { what: "the output buffer" }`, rebuild the message
   with `truncation = true`, `answers`, `authorities` and `additionals` cleared,
   **`edns` carried over untouched** (the size limit is itself signalled via
   EDNS), into a buffer of `max(max_len, 512)`.
4. Any other `WireError` propagates — it is a real failure to encode.

Sizing the scratch to `max_len` is what turns "the message does not fit" from a
comparison into an error, which is why it has to be caught rather than
propagated.

---

## 1.4 EDNS0 (RFC 6891)

`Edns` carries `udp_payload_size` (the OPT CLASS field), `version`, `do_bit`,
and **the option list unparsed** as `Box<[u8]>`.

The option list is deliberately not parsed during message parsing: a malformed
list must not make `DnsMessage::try_from_bytes` fail, or the FORMERR that answers
it could not be built.

| accessor | question answered |
|---|---|
| `has_edns()` | does the message carry an OPT record at all — infallible, used for OPT mirroring |
| `edns()` | the OPT record, if any — infallible |
| `edns_header()` | the three parameters a server acts on, **with the option list checked**; `Err` is the caller's cue to answer FORMERR |
| `udp_payload_size()` | the advertised size floored at 512 (RFC 6891 §6.2.3), or 512 with no OPT |
| `Edns::options()` | the parsed list; `Err` on a malformed one |

`EdnsHeader` is a `Copy` struct of the three fields, so the answer path never
builds a `Vec<EdnsOption>`.

Named option codes (round-tripped as opaque bytes, never interpreted): NSID (3),
Client Subnet (8), Cookie (10), Padding (12).

**EDNS version handling.** Only version 0 is implemented (`EDNS_VERSION`). A
request at a higher version MUST be answered BADVERS (16) with a bare version-0
OPT record carrying the extended code's high bits.

---

## 1.5 TCP framing (RFC 1035 §4.2.2)

Every message on TCP is preceded by a 2-octet big-endian length.

**Reading**, in all five read loops: read exactly 2 bytes, then exactly that many.
A zero length is treated as a broken peer and closes the connection.

**Timeouts**, where they exist (`rdnsd`, `rdnsr`): the connection may sit idle
between messages for `TCP_IDLE_TIMEOUT` (10 s), but once a length prefix has
arrived the peer has committed and gets `TCP_READ_TIMEOUT` (5 s) for the body.

**Writing**: the prefix and the message go into one buffer so the writer emits
both in a single call.

> **Deviation D-2 — fixed 2026-08-03.** ~~Every writer computes the prefix as
> `bytes.len() as u16` with no check, in five places, so a message longer than
> 65535 octets would be framed with a wrapped length.~~ There is one writer now,
> `rdns::framed`, and it returns `WireError::TooLong` rather than casting. See
> `07-rfc-conformance.md`.

---

## 1.6 TSIG (RFC 8945)

`rdns/src/tsig.rs`. Algorithms: `hmac-sha256` (default), and the others
`TsigAlgorithm` names.

- **The TSIG record is the last record in the additional section**, appended to
  the finished message bytes with ARCOUNT incremented in place
  (`append_tsig`, `tsig.rs:844`). Its owner name is written **uncompressed**, so
  the record can be removed by truncating the message.
- `tsig::check_request` returns `Unsigned`, `Verified(TsigSession)` or
  `Rejected(...)`. Verification happens **before** anything that could answer.
- A signed request earns a signed answer, from the same session, so the reply's
  MAC covers the request's — which is what stops a reply to one question being
  replayed as the reply to another.
- **A refusal to a signed request is itself signed** (RFC 8945 §5.3). This
  applies to every error path, not only to the authorized ones.
- For a multi-message transfer the MACs chain (RFC 8945 §5.3.1), so a dropped or
  reordered envelope fails at the client rather than passing for a complete zone.
- A `TsigKey` may be scoped to a list of zones. See `03-authoritative-server.md`
  §3.4 for the authorization rule, which is separate from authentication.

---

## 1.7 Error taxonomy on this path

`WireError` (`rdns/src/error.rs`), and the decision each variant feeds:

| variant | means | server answers |
|---|---|---|
| `Truncated { what, need, have }` | the message ran out | FORMERR |
| `TooLong { what, limit, actual }` | a field exceeded its limit | FORMERR |
| `Malformed { what, why }` | structurally wrong | FORMERR |
| `Unsupported { what }` | legal but not implemented (binary labels) | NOTIMP |

`RequestError::NotAQuestion` is **not** a `WireError`: a packet that decoded
perfectly but has QR=1 earns no reply at all. See `03-authoritative-server.md`
§3.1.
