# 1. Wire format

Implemented in `rdns/src/lib.rs`, `dname.rs`, `compression.rs`, `record_data.rs`
and `tsig.rs`.

---

## 1.1 Domain names

### Representation

A name is a Rust `String` in presentation form: labels separated by `.`, absolute
names carrying a trailing `.`. There is no label-vector or wire-byte
representation anywhere in the library.

- A label containing `.` or `\` is refused, not escaped — `dname.rs:75`
  (`unrepresentable_octet`), at the decode boundary and at `write_label`. The
  decode arm returns `WireError::Unsupported`. Escaping `.` would make the
  presentation form non-injective; a `\` cannot be written into a zone file this
  reader reads back as the same name.
- A label that is not valid UTF-8 is refused (`dname.rs:143`) with
  `WireError::Malformed`. RFC 2181 §11 permits any binary string, so this is
  deviation D-1.

### Limits enforced

| limit | value | where | RFC |
|---|---|---|---|
| label length | 63 octets | `write_label`, `Label::try_from_bytes` | 1035 §2.3.4 |
| name length, encoded | 255 octets | `UnpackedDName::new` (parse) and the encode path | 1035 §2.3.4 |
| empty label | refused | `write_label` | 1035 §3.1 |
| label syntax (LDH) | not enforced | `dname.rs:235` | 2181 §11 — see D-5 |

The 255-octet limit counts each label's length octet and the terminating zero,
and is checked in both directions through one helper, `dname::check_name_len`
(`dname.rs:466`).

### Compression (RFC 1035 §4.1.4)

Decoding (`DNameUnpacker::unpack_internal`, `dname.rs:295`):

- A pointer's 14-bit offset MUST be within the message, or the parse fails.
- Every pointer after the first in a chain MUST target a strictly lower offset
  than the previous one, so cycles are unreachable rather than detected.
- The first hop is unconstrained and may jump forward (deviation D-6).
- Pointer nesting is capped at 50 hops (`MAX_DEPTH`).
- Extended label types (RFC 2673 binary labels `0x41`, and `0x7f`) return
  `WireError::Unsupported`, answered NOTIMP. Any other extended type is
  `Malformed` (FORMERR).

Encoding (`compression.rs`): owner names are compressed against everything
already written. RDATA is stored uncompressed and wire-ready and copied verbatim,
except for the record types whose embedded names may legally be compressed, which
`NameCompressor::write_rdata` handles.

### Case folding

ASCII only (RFC 4343), everywhere: `utils::ascii_lowered`,
`utils::ascii_lowered_cow`, `utils::names_equal`, `utils::absolute_lowered`.
`str::to_lowercase` MUST NOT be used on a name — it folds U+212A KELVIN SIGN onto
`k`.

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

The OPT record is a field, not an additional record, so two OPT records in one
message are unspellable (RFC 6891 §6.1.1). The parser rejects a second OPT with
`WireError::Malformed` (`lib.rs:1716`). ARCOUNT is computed as
`additionals.len() + edns.is_some()`.

### Header parsing

- A packet shorter than 12 octets is `Truncated`.
- OPCODE is `hi >> 3` masked to 4 bits, and total: `OpCode::Other(u8)` carries
  the values with no name here, and `from_u8`/`to_u8` are exact inverses over the
  whole range (RFC 1035 §4.1.1).
- RCODE is reassembled to 12 bits: low 4 from the header, high 8 from the OPT
  flags word (RFC 6891 §6.1.3). `ResponseCode::Other(u16)` carries unknown codes;
  `from_u16`/`to_u16` are inverses. An unrecognised failure code MUST NOT be
  relayed as NOERROR.

### Type and class spaces

| type | meaning | conversions |
|---|---|---|
| `Rtype(u16)` | a record's TYPE | `Rtype -> Qtype` exists; the reverse does not |
| `Qtype(u16)` | a question's QTYPE | compare only via `Qtype::matches` / `Qtype::is` |
| `Class(u16)` | a record's CLASS | `Class -> QueryClass` exists; the reverse does not |
| `QueryClass` | a question's QCLASS | `matches` / `is` |

- `Qtype::matches(rtype)` is the only comparison of a question's type against
  stored data. `Qtype::ANY` matches every type except RRSIG, NSEC and NSEC3,
  which are not answer-section data unless DO asked for them (RFC 4035 §3.1.1).
- `Rtype::is_meta()` is true for ANY (255), AXFR (252) and IXFR (251) — values a
  TYPE field can carry (RFC 2136 §2.4/§2.5) but no stored record can have.
- `Class::is_meta()` is true for NONE (254) and ANY (255).
- `QueryClass::matches(class)` treats QCLASS ANY as matching every class
  (RFC 1035 §3.2.5).

### TTL

`Ttl(u32)`. `Ttl::from_wire(i32)` clamps a negative wire value to zero
(RFC 2181 §8) and is the only place the sign of the field is considered. An OPT
record's TTL never goes through it: it is a flags word, read raw as `u32` in
`Additional::try_from_bytes`.

### Serial

`Serial(u32)`, with no `PartialOrd` and no `Ord`. `Serial::is_newer_than`
implements RFC 1982 §3.2: `forward = self.wrapping_sub(other); forward != 0 &&
forward < 2^31`. Equal serials are not newer, and two serials exactly half the
space apart answer `false` in both directions. `Serial::wrapping_add` is the
defined addition in the sequence space.

### RDATA storage

`RecordData` (`record_data.rs`) holds `(Rtype, Box<[u8]>)` with private fields in
a one-struct module, so a value can only be built through a checking constructor.
`RecordData::parse()` produces a typed `ParsedRecord` on demand; the parsed form
is never stored.

RDLENGTH = 0 is legal and parses to `ParsedRecord::Unknown(rtype)`
(`lib.rs:581`) — RFC 2136 §2.4.1/§2.4.2/§2.5.2/§2.5.3 spell prerequisites and
RRset deletions that way.

Typed record types: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, DNSKEY, RRSIG, DS,
NSEC, NSEC3. Everything else is `Unknown(Rtype)` with bytes preserved verbatim.

TXT is `Vec<Vec<u8>>` — a sequence of `<character-string>`s (RFC 1035 §3.3.14),
each at most 255 octets, stored as bytes. A TXT record holding two strings is a
different record from one holding them joined. Encoding a TXT with zero strings
is an error.

RRSIG field order on the wire is expiration then inception (RFC 4034 §3.1).

### Length checks

Every length off the wire is checked before use: `read_be!` checks its own bytes,
`Label::try_from_bytes` checks before slicing, `Edns::walk_options` checks each
TLV, and `read_record_parts` checks RDLENGTH against the remaining message before
`split_at` (`lib.rs:1548`).

---

## 1.3 Serialization

`DnsMessage::to_bytes(&mut [u8]) -> Result<usize>` writes into a caller-owned
buffer through `write_bytes`, which refuses to write past the end rather than
truncating silently.

- RCODE above `0xfff` is an error.
- RCODE above `0xf` with no OPT record is an error — nowhere to put the high bits.
- RDLENGTH, ARCOUNT and OPT RDLENGTH that do not fit `u16` are `TooLong`.
- The OPT record is written last in the additional section, so `append_tsig`
  leaves the TSIG final as RFC 8945 §5.1 requires.

### Truncation

`to_bytes_within(max_len)` / `to_bytes_within_buf(max_len, &mut Vec<u8>)`:

1. Serialize into a scratch buffer of exactly `max_len` bytes.
2. On success within the limit, return those bytes.
3. On `WireError::Truncated { what: "the output buffer" }`, rebuild with
   `truncation = true`, `answers`/`authorities`/`additionals` cleared, and `edns`
   carried over untouched, into a buffer of `max(max_len, 512)`.
4. Any other `WireError` propagates.

---

## 1.4 EDNS0 (RFC 6891)

`Edns` carries `udp_payload_size` (the OPT CLASS field), `version`, `do_bit`, and
the option list unparsed as `Box<[u8]>`. The list is not parsed during message
parsing, so a malformed one cannot stop the FORMERR that answers it being built.

| accessor | question answered |
|---|---|
| `has_edns()` | does the message carry an OPT record at all — infallible, used for OPT mirroring |
| `edns()` | the OPT record, if any — infallible |
| `edns_header()` | the three parameters a server acts on, with the option list checked; `Err` is the caller's cue to answer FORMERR |
| `udp_payload_size()` | the advertised size floored at 512 (RFC 6891 §6.2.3), or 512 with no OPT |
| `Edns::options()` | the parsed list; `Err` on a malformed one |

`EdnsHeader` is a `Copy` struct of the three fields.

Named option codes, round-tripped as opaque bytes and never interpreted: NSID
(3), Client Subnet (8), Cookie (10), Padding (12).

Only EDNS version 0 is implemented (`EDNS_VERSION`). A request at a higher
version MUST be answered BADVERS (16) with a bare version-0 OPT record.

---

## 1.5 TCP framing (RFC 1035 §4.2.2)

Every message on TCP is preceded by a 2-octet big-endian length, written by
`rdns::framed`, which returns `WireError::TooLong` rather than casting.

Reading, in all five read loops: read exactly 2 bytes, then exactly that many. A
zero length is treated as a broken peer and closes the connection.

Timeouts (`rdnsd`, `rdnsr`): the connection may sit idle between messages for
`TCP_IDLE_TIMEOUT` (10 s); once a length prefix has arrived the peer gets
`TCP_READ_TIMEOUT` (5 s) for the body.

Writing: the prefix and the message go into one buffer.

> Deviation D-2 — fixed 2026-08-03. ~~Every writer computes the prefix as
> `bytes.len() as u16` with no check, in five places.~~ See
> `07-rfc-conformance.md`.

---

## 1.6 TSIG (RFC 8945)

`rdns/src/tsig.rs`. Algorithms: `hmac-sha256` (default) and the others
`TsigAlgorithm` names.

- The TSIG record is the last record in the additional section, appended to the
  finished message bytes with ARCOUNT incremented in place (`append_tsig`,
  `tsig.rs:844`). Its owner name is written uncompressed, so the record can be
  removed by truncating the message.
- `tsig::check_request` returns `Unsigned`, `Verified(TsigSession)` or
  `Rejected(...)`. Verification happens before anything that could answer.
- A signed request earns a signed answer from the same session, so the reply's
  MAC covers the request's.
- A refusal to a signed request is itself signed (RFC 8945 §5.3), on every error
  path.
- For a multi-message transfer the MACs chain (RFC 8945 §5.3.1).
- A `TsigKey` may be scoped to a list of zones; the authorization rule is in
  `03-authoritative-server.md` §3.4.

---

## 1.7 Error taxonomy on this path

`WireError` (`rdns/src/error.rs`), and the decision each variant feeds:

| variant | means | server answers |
|---|---|---|
| `Truncated { what, need, have }` | the message ran out | FORMERR |
| `TooLong { what, limit, actual }` | a field exceeded its limit | FORMERR |
| `Malformed { what, why }` | structurally wrong | FORMERR |
| `Unsupported { what }` | legal but not implemented (binary labels) | NOTIMP |

`RequestError::NotAQuestion` is not a `WireError`: a packet that decoded
perfectly but has QR=1 earns no reply at all. See `03-authoritative-server.md`
§3.1.
