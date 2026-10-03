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
