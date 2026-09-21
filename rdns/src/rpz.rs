//! Response Policy Zones: the operator's answer in place of the internet's.
//!
//! Not an RFC. ISC's `draft-vixie-dns-rpz-04` is the specification, and BIND,
//! Knot Resolver, Unbound and PowerDNS all implement it — which is what makes it
//! the interface a blocking obligation is delivered through. A court order, a
//! police list and a malware feed arrive as the same thing: a DNS zone whose
//! owner names are *triggers* and whose RRsets are *actions*. Everything about
//! getting one here is machinery that already exists (a zone file, AXFR, IXFR,
//! NOTIFY); what is new is only reading one as policy.
//!
//! A trigger name is the thing matched with the policy zone's origin appended:
//! the QNAME `evil.example.` is looked for at `evil.example.<origin>`. So the
//! lookup is an ordinary zone lookup — [`Zone::locate`], wildcards and all
//! (RFC 1034 §4.3.3) — rather than a second name matcher written here.
//!
//! All five trigger types are implemented. QNAME, client IP and response IP are
//! answerable from what the answer path already holds. The other two are about
//! the *nameservers* a name is resolved through — `<nsname>.rpz-nsdname` and
//! `<prefix>.<addr>.rpz-nsip` — which the answer does not carry, so they are
//! asked while the delegation chain is being walked, through
//! [`crate::resolver::NameserverPolicy`]: a match stops the resolution rather
//! than rewriting its result, which is what the trigger is for (`TODO.md` #56).
//!
//! A stopped resolution caches nothing, so the block holds for every client
//! rather than the first one — provided the walk actually happens. It need not:
//! `resolve_from_root` starts at the deepest delegation it already knows, which
//! is why the delegation cache keeps the referral's NS names and the policy is
//! asked there too.
//!
//! Two deviations from BIND worth knowing, both deliberate:
//!
//! - **A rewrite applies to a DNSSEC-aware client too.** BIND's
//!   `break-dnssec no` default declines to rewrite a signed answer for a client
//!   that set DO, on the grounds that the client would see a forgery. That makes
//!   the block bypassable by setting one bit, which is not a block. The answer
//!   goes out with AD clear, as every synthesized answer here does.
//! - **Zone precedence is per pass, not per zone.** The specification consults
//!   policy zones in order and lets the first zone with *any* trigger match win;
//!   here the QNAME and client-IP triggers of every zone are tried before any
//!   zone's response-IP triggers, because a response-IP match costs the
//!   resolution a QNAME block exists to avoid. Only a configuration mixing the
//!   two kinds across zones can tell the difference.

use crate::error::{ConfigError, ConfigResult};
use crate::record_types as rt;
use crate::resolver::NameserverPolicy;
use crate::zone::{parse_zone_text_at, FileDigest, Located, NameKind, Zone, ZoneRecordRef};
use crate::zone_writer::Written;
use crate::{Name, NameRef, ParsedRecord, Qtype, ResourceRecord, Serial};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};

/// What a policy zone says to do with a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `CNAME .` — the name does not exist.
    Nxdomain,
    /// `CNAME *.` — the name exists and has nothing of this type.
    Nodata,
    /// `CNAME rpz-passthru.` — matched, and deliberately not rewritten. An
    /// exception carved out of a broader rule in the same zone.
    Passthru,
    /// `CNAME rpz-drop.` — no reply at all.
    Drop,
    /// `CNAME rpz-tcp-only.` — truncate over UDP, so the client comes back over
    /// TCP and a spoofed source gets nothing.
    TcpOnly,
    /// Anything else at the trigger: the RRset answers the query, owner name
    /// rewritten to the name that was asked for.
    LocalData(Vec<ResourceRecord>),
}

/// Which trigger matched, for the log line an operator reads when a customer
/// asks why a name does not resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Qname,
    ClientIp,
    ResponseIp,
    Nsdname,
    Nsip,
}

impl std::fmt::Display for Trigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Trigger::Qname => "qname",
            Trigger::ClientIp => "client-ip",
            Trigger::ResponseIp => "response-ip",
            Trigger::Nsdname => "nsdname",
            Trigger::Nsip => "nsip",
        })
    }
}

/// A match: what to do, and what the answer and the log need about where it
/// came from.
#[derive(Debug, Clone)]
pub struct Rewrite {
    pub action: Action,
    /// The policy zone that matched.
    pub zone: Name,
    pub trigger: Trigger,
    /// That zone's SOA, which a negative rewrite puts in the authority section
    /// so the answer can be cached at all (RFC 2308 §5).
    pub soa: Option<ResourceRecord>,
}

/// What to do with a match when the operator does not want what the zone says.
///
/// BIND's per-zone `policy`. `Given` is the zone's own action and the default;
/// the rest override every action in the zone, which is how a new feed is
/// evaluated (`Passthru` — match, log, change nothing) or narrowed to one
/// behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyOverride {
    /// Do what the zone says.
    #[default]
    Given,
    /// Load the zone and match nothing: an off switch that keeps the
    /// configuration, so turning a feed off is not deleting it.
    Disabled,
    Passthru,
    Drop,
    Nxdomain,
    Nodata,
    TcpOnly,
}

impl FromStr for PolicyOverride {
    type Err = ConfigError;

    fn from_str(s: &str) -> ConfigResult<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "given" => PolicyOverride::Given,
            "disabled" => PolicyOverride::Disabled,
            "passthru" => PolicyOverride::Passthru,
            "drop" => PolicyOverride::Drop,
            "nxdomain" => PolicyOverride::Nxdomain,
            "nodata" => PolicyOverride::Nodata,
            "tcp-only" => PolicyOverride::TcpOnly,
            other => {
                return Err(ConfigError::new(format!(
                    "unknown RPZ policy {other:?}: one of given, disabled, passthru, \
                     drop, nxdomain, nodata, tcp-only"
                )))
            }
        })
    }
}

impl std::fmt::Display for PolicyOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PolicyOverride::Given => "given",
            PolicyOverride::Disabled => "disabled",
            PolicyOverride::Passthru => "passthru",
            PolicyOverride::Drop => "drop",
            PolicyOverride::Nxdomain => "nxdomain",
            PolicyOverride::Nodata => "nodata",
            PolicyOverride::TcpOnly => "tcp-only",
        })
    }
}

impl PolicyOverride {
    /// The action actually taken, given what the zone said.
    fn apply(self, given: Action) -> Option<Action> {
        Some(match self {
            PolicyOverride::Given => given,
            PolicyOverride::Disabled => return None,
            PolicyOverride::Passthru => Action::Passthru,
            PolicyOverride::Drop => Action::Drop,
            PolicyOverride::Nxdomain => Action::Nxdomain,
            PolicyOverride::Nodata => Action::Nodata,
            PolicyOverride::TcpOnly => Action::TcpOnly,
        })
    }
}

/// One feed: the file it is read from, and what its rules mean.
///
/// A policy per feed and not one for the set, because that is how a feed is
/// introduced: the new one runs in `passthru` while the others stay enforced
/// (`TODO.md` #63j). The command line cannot say it — `--rpz-policy` is one
/// setting for every `--rpz` — so [`Feed::each`] is the flags' shape of it.
#[derive(Debug, Clone)]
pub struct Feed {
    pub path: PathBuf,
    pub policy: PolicyOverride,
}

impl Feed {
    pub fn new(path: impl Into<PathBuf>, policy: PolicyOverride) -> Feed {
        Feed {
            path: path.into(),
            policy,
        }
    }

    /// Every path at one policy, in order — what a command line can express.
    pub fn each(paths: &[PathBuf], policy: PolicyOverride) -> Vec<Feed> {
        paths.iter().map(|p| Feed::new(p.clone(), policy)).collect()
    }
}

/// The label that ends the owner name of every trigger type that is not a
/// QNAME.
///
/// A query name whose own last label is one of these would otherwise build a
/// trigger name inside one of those subtrees and match an address rule by
/// accident.
const SPECIAL_LABELS: [&[u8]; 4] = [b"rpz-client-ip", b"rpz-ip", b"rpz-nsdname", b"rpz-nsip"];

/// One address rule as it parses: the prefix it covers, and the owner name
/// whose RRset is the action.
#[derive(Debug, Clone)]
struct IpTrigger {
    addr: IpAddr,
    prefix: u8,
    owner: Name,
}

/// A run of addresses one rule owns, the address widened to `u128` for both
/// families.
///
/// One width rather than a `u32` table beside a `u128` one: it measured
/// *faster* for v4 as well — 9.5 ns against 14.7 at 50 000 rules — and a
/// second code path here is where the two would drift (§7).
#[derive(Debug, Clone, Copy)]
struct Span {
    lo: u128,
    hi: u128,
    /// Into [`IpIndex::owners`]. `usize` costs nothing a `u32` would save:
    /// the struct is 16-aligned either way.
    owner: usize,
}

/// The address triggers of one kind, indexed for longest-prefix match.
///
/// Overlapping rules are flattened once, at index time, into disjoint spans in
/// address order with the winning rule already chosen, so a query is one
/// binary search. It was a scan of every rule, under a comment calling these
/// lists "tens of entries": nothing enforced that, and an IP blocklist
/// delivered as RPZ is all `rpz-ip`. On the miss path every ordinary query
/// pays, 50 000 rules cost the scan 144.6 µs and cost this 7 ns — against
/// 522 ns for a whole answer (`TODO.md` #62a).
#[derive(Debug, Default)]
struct IpIndex {
    /// The families never mix, as in [`crate::security::TransferAcl`]: a v4
    /// rule must not match a v4-mapped v6 peer. Two tables is how that holds
    /// without a comparison to forget.
    v4: Vec<Span>,
    v6: Vec<Span>,
    /// One entry per rule, so its length is the trigger count the banner
    /// wants; the spans are more numerous, since nesting splits them.
    owners: Vec<Name>,
}

impl IpIndex {
    fn new(rules: Vec<IpTrigger>) -> IpIndex {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut owners = Vec::with_capacity(rules.len());
        for rule in rules {
            let (bits, addr, table) = match rule.addr {
                IpAddr::V4(a) => (32u8, u128::from(u32::from(a)), &mut v4),
                IpAddr::V6(a) => (128u8, u128::from(a), &mut v6),
            };
            // The host bits the prefix leaves free. Saturating because a
            // prefix longer than its family's address is not a rule —
            // `parse_ip_trigger` refuses one — and if one arrived anyway it
            // must cover a single address rather than all of them.
            let free = match bits.saturating_sub(rule.prefix) {
                0 => 0,
                // `1 << 128` is not representable, which is why the mask is
                // shifted down rather than built up.
                free => u128::MAX >> (128 - u32::from(free)),
            };
            let lo = addr & !free;
            table.push(Span {
                lo,
                hi: lo | free,
                owner: owners.len(),
            });
            owners.push(rule.owner);
        }
        IpIndex {
            v4: flatten(v4),
            v6: flatten(v6),
            owners,
        }
    }

    fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    fn len(&self) -> usize {
        self.owners.len()
    }

    /// The owner name of the longest prefix covering `addr`, if any covers it.
    fn owner_of(&self, addr: IpAddr) -> Option<NameRef<'_>> {
        let (table, addr) = match addr {
            IpAddr::V4(a) => (&self.v4, u128::from(u32::from(a))),
            IpAddr::V6(a) => (&self.v6, u128::from(a)),
        };
        // The spans are disjoint and sorted, so the last one starting at or
        // below the address is the only one that can hold it.
        let span = table.get(table.partition_point(|s| s.lo <= addr).checked_sub(1)?)?;
        (addr <= span.hi).then(|| self.owners[span.owner].as_ref())
    }
}

/// Flatten overlapping rules into disjoint spans in address order, each
/// carrying the rule that wins it: the longest prefix, and at equal prefixes
/// the one that came first in the zone — which is what the scan this replaced
/// gave, by sorting on the prefix with a stable sort and taking the first hit.
///
/// A stack sweep, because prefixes nest: two of them are either disjoint or
/// one contains the other, so the innermost rule still open is always the most
/// specific one covering the cursor.
fn flatten(mut spans: Vec<Span>) -> Vec<Span> {
    // A containing span sorts before what it contains, and of two identical
    // ranges the *later* rule is pushed first so the earlier one ends on top.
    spans.sort_by(|a, b| {
        a.lo.cmp(&b.lo)
            .then(b.hi.cmp(&a.hi))
            .then(b.owner.cmp(&a.owner))
    });

    let mut out: Vec<Span> = Vec::new();
    let mut open: Vec<Span> = Vec::new();
    let mut cursor = 0u128;
    // Adjacent runs of one rule are one span: a /24 split by a /32 inside it
    // is two pieces, not three hundred.
    let emit = |out: &mut Vec<Span>, lo, hi, owner| match out.last_mut() {
        Some(last) if last.owner == owner && last.hi.wrapping_add(1) == lo => last.hi = hi,
        _ => out.push(Span { lo, hi, owner }),
    };

    for span in spans {
        while let Some(top) = open.last().copied() {
            if top.hi >= span.lo {
                break;
            }
            if cursor <= top.hi {
                emit(&mut out, cursor, top.hi, top.owner);
                cursor = top.hi + 1;
            }
            open.pop();
        }
        if cursor < span.lo {
            if let Some(top) = open.last() {
                emit(&mut out, cursor, span.lo - 1, top.owner);
            }
            cursor = span.lo;
        }
        open.push(span);
    }
    while let Some(top) = open.pop() {
        if cursor <= top.hi {
            emit(&mut out, cursor, top.hi, top.owner);
            // A rule reaching the end of the space leaves nowhere to advance
            // to, and `+ 1` there would wrap into the bottom of it.
            if top.hi == u128::MAX {
                break;
            }
            cursor = top.hi + 1;
        }
    }
    out.shrink_to_fit();
    out
}

/// A feed's file, as text.
///
/// The error names the file, because a resolver runs several and "no such file"
/// on its own sends the operator to the wrong one.
fn read_feed(path: &Path) -> ConfigResult<String> {
    std::fs::read_to_string(path)
        .map_err(|e| ConfigError::new(format!("RPZ {}: {e}", path.display())))
}

/// Where a policy zone was read from, when a reload could keep it rather than
/// read it again (`TODO.md` #71b).
///
/// Absent for a zone built in memory, and for a file that `$INCLUDE`s another —
/// [`FileDigest::of_self_contained`] says why that one has to be read every
/// time.
#[derive(Debug)]
struct ReadFrom {
    path: PathBuf,
    digest: FileDigest,
}

/// One policy zone, indexed for the three questions a query asks of it.
#[derive(Debug)]
pub struct PolicyZone {
    zone: Zone,
    policy: PolicyOverride,
    read_from: Option<ReadFrom>,
    client_ip: IpIndex,
    response_ip: IpIndex,
    ns_ip: IpIndex,
    /// `rpz-nsdname.<origin>`, the parent of every NSDNAME trigger name, built
    /// once rather than per delegation.
    nsdname_root: Name,
    /// How many NSDNAME triggers the zone holds. A zone with none skips the
    /// lookup: a feed's bulk is QNAME rules and every delegation of every
    /// query would otherwise pay a zone lookup per nameserver.
    nsdname: usize,
}

impl PolicyZone {
    /// Read a policy zone from a file. The origin comes from the file's
    /// `$ORIGIN` line, or from the file's own name as a fallback — the rule
    /// `rdnsd` names a zone in a directory by.
    pub fn load(path: &Path, policy: PolicyOverride) -> ConfigResult<PolicyZone> {
        let text = read_feed(path)?;
        PolicyZone::parse(path, &text, policy)
    }

    /// The same, for a caller that has already read the file — which
    /// [`PolicyZones::reload`] has, because deciding whether to parse at all is
    /// what it read the bytes for.
    fn parse(path: &Path, text: &str, policy: PolicyOverride) -> ConfigResult<PolicyZone> {
        let fallback = crate::zone::origin_from_path(&path.to_string_lossy());
        let zone = parse_zone_text_at(text, &fallback, path)
            .map_err(|e| ConfigError::new(format!("RPZ {}: {e}", path.display())))?;
        PolicyZone::from_text(zone, policy, path, text)
    }

    /// Index a zone this process holds, as read from the text it was written
    /// as — [`PolicyZones::reload`]'s test is over the file's bytes, so a zone
    /// carries the digest of the bytes that represent it whether it was parsed
    /// out of them or serialized into them (`TODO.md` #71f).
    fn from_text(
        zone: Zone,
        policy: PolicyOverride,
        path: &Path,
        text: &str,
    ) -> ConfigResult<PolicyZone> {
        let mut indexed = PolicyZone::new(zone, policy)?;
        indexed.read_from = FileDigest::of_self_contained(text.as_bytes()).map(|digest| ReadFrom {
            path: path.to_path_buf(),
            digest,
        });
        Ok(indexed)
    }

    /// The same, for a zone this process serialized and wrote rather than read.
    ///
    /// [`Written`] already holds the path and the digest of the bytes that
    /// reached the file, so there is nothing here to get out of step with them.
    fn from_written(
        zone: Zone,
        policy: PolicyOverride,
        written: &Written,
    ) -> ConfigResult<PolicyZone> {
        let mut indexed = PolicyZone::new(zone, policy)?;
        indexed.read_from = written.digest().map(|digest| ReadFrom {
            path: written.path().to_path_buf(),
            digest,
        });
        Ok(indexed)
    }

    /// Index a parsed zone as policy.
    ///
    /// The SOA is required rather than optional: a rewrite to NXDOMAIN owes an
    /// authority record or the client cannot cache the answer (RFC 2308 §5),
    /// and a policy zone without one could not have arrived by transfer either.
    pub fn new(zone: Zone, policy: PolicyOverride) -> ConfigResult<PolicyZone> {
        if zone.apex_soa_record().is_none() {
            return Err(ConfigError::new(format!(
                "the policy zone {} has no SOA at its apex",
                zone.origin().to_presentation()
            )));
        }
        let origin = zone.origin();
        let mut client_ip = Vec::new();
        let mut response_ip = Vec::new();
        let mut ns_ip = Vec::new();
        let mut nsdname = 0;
        // A set, not a `Vec` scanned per record: an IP blocklist delivered as
        // RPZ is all `rpz-ip` rules and the scan was quadratic in them — 400 ms
        // to index 16k, four times that per doubling (`TODO.md` #62b). `Name`'s
        // `Hash` is the ASCII fold (RFC 4343), the comparison the scan made.
        let mut seen: HashSet<Name> = HashSet::new();
        for record in zone.records() {
            let owner = record.name;
            let Some(kind) = trigger_subtree(owner, origin) else {
                continue;
            };
            // One rule per owner name, however many records sit at it.
            if !seen.insert(record.name.to_owned()) {
                continue;
            }
            // An NSDNAME trigger's labels are a name, not an address; the
            // lookup that matches one is the zone's own, so nothing is indexed
            // here beyond knowing whether to try it at all.
            if kind == b"rpz-nsdname" {
                nsdname += 1;
                continue;
            }
            let labels: Vec<&[u8]> = owner
                .labels()
                .take(owner.label_count() - origin.label_count() - 1)
                .collect();
            let (addr, prefix) = parse_ip_trigger(&labels).map_err(|why| {
                ConfigError::new(format!(
                    "the policy zone {} has a trigger {} that is not an address: {why}",
                    origin.to_presentation(),
                    owner.to_presentation()
                ))
            })?;
            let trigger = IpTrigger {
                addr,
                prefix,
                owner: record.name.to_owned(),
            };
            match kind {
                b"rpz-client-ip" => client_ip.push(trigger),
                b"rpz-nsip" => ns_ip.push(trigger),
                _ => response_ip.push(trigger),
            }
        }
        let client_ip = IpIndex::new(client_ip);
        let response_ip = IpIndex::new(response_ip);
        let ns_ip = IpIndex::new(ns_ip);

        let nsdname_root = Name::prefixed(b"rpz-nsdname", origin).map_err(|e| {
            ConfigError::new(format!(
                "the policy zone {} is too long to hold NSDNAME triggers: {e}",
                origin.to_presentation()
            ))
        })?;

        Ok(PolicyZone {
            zone,
            policy,
            read_from: None,
            client_ip,
            response_ip,
            ns_ip,
            nsdname_root,
            nsdname,
        })
    }

    /// Whether this zone is what `path` held when it was last read or written.
    fn was_read_from(&self, path: &Path) -> bool {
        self.read_from
            .as_ref()
            .is_some_and(|from| from.path == path)
    }

    pub fn origin(&self) -> NameRef<'_> {
        self.zone.origin()
    }

    /// The zone behind the index, for a refresh that has to say which version
    /// it holds (`TODO.md` #57e). Read-only: the index is built from these
    /// records and cannot be kept in step with an edit.
    pub fn zone(&self) -> &Zone {
        &self.zone
    }

    /// How many records the zone holds, for the startup banner: "the feed
    /// loaded" as a number rather than a claim.
    pub fn records(&self) -> usize {
        self.zone.records().len()
    }

    /// How many triggers of each kind the zone holds, for the startup banner:
    /// QNAME, client IP, response IP, NSDNAME, NSIP.
    ///
    /// The QNAME count is what is left after the four indexed kinds, which is
    /// the apex's own records too — a feed's SOA and NS are not rules, so this
    /// is "how big is the file" rather than a rule count, and the banner says
    /// so.
    pub fn trigger_counts(&self) -> [usize; 5] {
        let addressed = self.client_ip.len() + self.response_ip.len() + self.ns_ip.len();
        [
            self.records().saturating_sub(addressed + self.nsdname),
            self.client_ip.len(),
            self.response_ip.len(),
            self.nsdname,
            self.ns_ip.len(),
        ]
    }

    /// Whether this zone has anything to say about a delegation.
    fn watches_delegations(&self) -> bool {
        self.nsdname > 0 || !self.ns_ip.is_empty()
    }

    pub fn policy(&self) -> PolicyOverride {
        self.policy
    }

    /// The action for a query name, or `None` if this zone says nothing.
    fn qname_action(&self, qname: NameRef<'_>, qtype: Qtype) -> Option<Action> {
        // `something.rpz-ip.` as a query name would otherwise land on an
        // address rule. `None` at the root, whose trigger name is the apex —
        // where the SOA is, not a rule.
        let last = qname.labels().last()?;
        if SPECIAL_LABELS.iter().any(|l| last.eq_ignore_ascii_case(l)) {
            return None;
        }
        let trigger = Name::concat(qname, self.zone.origin()).ok()?;
        self.action_at(trigger.as_ref(), qname, qtype)
    }

    fn client_action(&self, client: IpAddr, qname: NameRef<'_>, qtype: Qtype) -> Option<Action> {
        self.ip_action(&self.client_ip, client, qname, qtype)
    }

    fn response_action(&self, addr: IpAddr, qname: NameRef<'_>, qtype: Qtype) -> Option<Action> {
        self.ip_action(&self.response_ip, addr, qname, qtype)
    }

    /// The action for one nameserver name: the trigger is that name under
    /// `rpz-nsdname.<origin>`, so a wildcard rule is an ordinary zone wildcard
    /// exactly as a QNAME rule's is.
    fn nsdname_action(&self, ns: NameRef<'_>, qname: NameRef<'_>, qtype: Qtype) -> Option<Action> {
        if self.nsdname == 0 {
            return None;
        }
        // As in `qname_action`: a nameserver called `something.rpz-ip.` would
        // otherwise build a trigger name inside an address subtree.
        let last = ns.labels().last()?;
        if SPECIAL_LABELS.iter().any(|l| last.eq_ignore_ascii_case(l)) {
            return None;
        }
        let trigger = Name::concat(ns, self.nsdname_root.as_ref()).ok()?;
        self.action_at(trigger.as_ref(), qname, qtype)
    }

    fn ns_ip_action(&self, addr: IpAddr, qname: NameRef<'_>, qtype: Qtype) -> Option<Action> {
        self.ip_action(&self.ns_ip, addr, qname, qtype)
    }

    fn ip_action(
        &self,
        rules: &IpIndex,
        addr: IpAddr,
        qname: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<Action> {
        let owner = rules.owner_of(addr)?;
        self.action_at(owner, qname, qtype)
    }

    /// The RRset at `trigger` read as an action, with this zone's policy
    /// applied to it.
    fn action_at(&self, trigger: NameRef<'_>, qname: NameRef<'_>, qtype: Qtype) -> Option<Action> {
        let located = self.zone.locate(trigger);
        let given = read_action(&located, qname, qtype)?;
        self.policy.apply(given)
    }

    fn rewrite(&self, action: Action, trigger: Trigger) -> Rewrite {
        Rewrite {
            action,
            zone: self.zone.origin().to_owned(),
            trigger,
            soa: self.zone.apex_soa_record(),
        }
    }
}

/// Which trigger subtree `owner` sits in, as the label that names it.
///
/// `None` for an ordinary QNAME trigger — the subtree names themselves
/// included, since those are the shape of the tree rather than rules.
fn trigger_subtree<'a>(owner: NameRef<'a>, origin: NameRef<'_>) -> Option<&'a [u8]> {
    let depth = owner.label_count().checked_sub(origin.label_count() + 1)?;
    if depth == 0 {
        return None;
    }
    let label = owner.labels().nth(depth)?;
    SPECIAL_LABELS
        .iter()
        .find(|special| label.eq_ignore_ascii_case(special))
        .copied()
}

/// The action an RRset states, or `None` if there is no rule at this name.
fn read_action(located: &Located<'_>, qname: NameRef<'_>, qtype: Qtype) -> Option<Action> {
    match located.kind() {
        // A name with descendants and no records of its own is the shape of the
        // tree, not a rule; a name that is not there is not a rule either.
        NameKind::NotFound | NameKind::EmptyNonTerminal => return None,
        NameKind::Exact | NameKind::Wildcard(_) => {}
    }

    // A CNAME is the action whatever the QTYPE: five of the six actions are
    // spelled as one, and the sixth is an ordinary redirect.
    if let Some(cname) = located.of_type(Qtype::of(rt::CNAME)).next() {
        if let Ok(ParsedRecord::CNAME(target)) = cname.rdata.parse() {
            if let Some(verb) = policy_verb(target.as_ref()) {
                return Some(verb);
            }
        }
        return Some(Action::LocalData(vec![rewritten(cname, qname)]));
    }

    let records: Vec<ResourceRecord> = located
        .of_type(qtype)
        .map(|record| rewritten(record, qname))
        .collect();
    // Data at the trigger but none of this type: the name exists and has
    // nothing of it, which is the answer a zone would give.
    if records.is_empty() {
        return Some(Action::Nodata);
    }
    Some(Action::LocalData(records))
}

/// The record as it goes into the answer: the trigger's RDATA under the name
/// the client asked about.
fn rewritten(record: ZoneRecordRef<'_>, qname: NameRef<'_>) -> ResourceRecord {
    ResourceRecord {
        name: qname.to_owned(),
        class: record.class,
        ttl: record.ttl,
        rdata: record.rdata.to_owned(),
    }
}

/// The five actions spelled as a CNAME target, or `None` for a real redirect.
fn policy_verb(target: NameRef<'_>) -> Option<Action> {
    if target.is_root() {
        return Some(Action::Nxdomain);
    }
    let mut labels = target.labels();
    let first = labels.next()?;
    // A verb is one label at the root; `rpz-drop.example.com.` is a name.
    if labels.next().is_some() {
        return None;
    }
    if first == b"*" {
        return Some(Action::Nodata);
    }
    if first.eq_ignore_ascii_case(b"rpz-passthru") {
        return Some(Action::Passthru);
    }
    if first.eq_ignore_ascii_case(b"rpz-drop") {
        return Some(Action::Drop);
    }
    if first.eq_ignore_ascii_case(b"rpz-tcp-only") {
        return Some(Action::TcpOnly);
    }
    None
}

/// `[prefix, part, part, ...]` — the labels of an address trigger, most
/// significant *last*, as `8.0.0.0.127` for 127.0.0.0/8.
///
/// IPv4 is four decimal octets; IPv6 is eight hexadecimal 16-bit words, or
/// fewer with one `zz` standing for the longest run of zeroes exactly as `::`
/// does. Four decimal parts within 0-255 under a prefix a v4 address can hold
/// are v4 — BIND's rule, and the only ambiguity the encoding has.
fn parse_ip_trigger(labels: &[&[u8]]) -> Result<(IpAddr, u8), String> {
    let (prefix, parts) = labels.split_first().ok_or("no labels")?;
    let prefix: u8 = text(prefix)?
        .parse()
        .map_err(|_| "the first label is not a prefix length".to_string())?;
    // Most significant first, the way an address is written.
    let parts: Vec<&str> = parts
        .iter()
        .rev()
        .map(|label| text(label))
        .collect::<Result<_, _>>()?;

    let v4 = parts.len() == 4 && prefix <= 32 && parts.iter().all(|p| p.parse::<u8>().is_ok());
    if v4 {
        let mut octets = [0u8; 4];
        for (out, part) in octets.iter_mut().zip(&parts) {
            *out = part
                .parse()
                .map_err(|_| format!("{part:?} is not an octet"))?;
        }
        return Ok((IpAddr::from(octets), prefix));
    }

    if prefix > 128 {
        return Err(format!("/{prefix} is longer than an address"));
    }
    let zeroes = parts
        .iter()
        .filter(|p| p.eq_ignore_ascii_case("zz"))
        .count();
    if zeroes > 1 {
        return Err("more than one `zz`".to_string());
    }
    if parts.len() > 8 || (zeroes == 0 && parts.len() != 8) {
        return Err(format!(
            "{} words and no `zz`, where an address has 8",
            parts.len()
        ));
    }
    let mut words = [0u16; 8];
    let filled = parts.len() - zeroes;
    let mut at = 0;
    for part in &parts {
        if part.eq_ignore_ascii_case("zz") {
            at += 8 - filled;
            continue;
        }
        words[at] =
            u16::from_str_radix(part, 16).map_err(|_| format!("{part:?} is not a hex word"))?;
        at += 1;
    }
    Ok((IpAddr::from(words), prefix))
}

/// A label as text. A trigger label is written by an operator or by a feed, so
/// non-ASCII in one is a malformed rule rather than something to guess at.
fn text(label: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(label).map_err(|_| "a label is not text".to_string())
}

/// The policy zones in force, in the order they are consulted.
///
/// Empty is the ordinary case and costs one `is_empty` per query:
/// [`PolicyZones::before_query`] returns before touching the name.
///
/// `Arc` per zone so that a reload can hand a feed nobody touched straight back
/// (`TODO.md` #71b). The zones are immutable once indexed — [`PolicyZone::zone`]
/// says why — so sharing one between the old set and the new one is sharing a
/// value neither can change.
#[derive(Debug, Default)]
pub struct PolicyZones {
    zones: Vec<Arc<PolicyZone>>,
}

impl PolicyZones {
    /// Load each feed, in the order they will be consulted.
    ///
    /// All-or-nothing: a feed that does not parse must not leave the resolver
    /// enforcing a policy shorter than the one configured (`CLAUDE.md` §4).
    pub fn load(feeds: &[Feed]) -> ConfigResult<PolicyZones> {
        PolicyZones::reload(feeds, &PolicyZones::default(), &PolicyZones::default())
    }

    /// The same, keeping every feed whose file has not moved since `held` read
    /// it — `TODO.md` #71b. Three million-rule feeds with one publisher cost
    /// **781 ms** where the whole set cost **2 200**, and a SIGHUP over a quiet
    /// set **62 ms** (`rdns/tests/rpz_install.rs`, release, the development
    /// machine).
    ///
    /// Still all-or-nothing, and that is the property the row said must not be
    /// lost: every feed is read and parsed before any of the set is built, so a
    /// half-written file still leaves the previous set whole. What changes is
    /// that the test is now per feed rather than per set — one feed publishing
    /// no longer re-parses the others.
    ///
    /// The bytes are read either way and the digest is taken over them rather
    /// than a `stat` — [`FileDigest`] says why, for all three callers of it
    /// (#104). Measured at a million rules: read and digest 21 ms per feed
    /// against ~720 for the parse and index it replaces, where `rdnsd`'s
    /// reload path measured 1.8% (#64f).
    ///
    /// `offered` is what this process wrote and did not throw away
    /// (`TODO.md` #71f): a zone from there is taken only when its digest is the
    /// digest of the bytes just read, so a file somebody else rewrote in the
    /// meantime is parsed as it would have been.
    pub fn reload(
        feeds: &[Feed],
        held: &PolicyZones,
        offered: &PolicyZones,
    ) -> ConfigResult<PolicyZones> {
        let mut zones = Vec::with_capacity(feeds.len());
        for feed in feeds {
            let text = read_feed(&feed.path)?;
            let digest = FileDigest::of_self_contained(text.as_bytes());
            match held
                .kept(feed, digest)
                .or_else(|| offered.kept(feed, digest))
            {
                Some(zone) => zones.push(zone),
                None => zones.push(Arc::new(PolicyZone::parse(&feed.path, &text, feed.policy)?)),
            }
        }
        Ok(PolicyZones { zones })
    }

    /// The zone this set holds for `feed`, when the file it was read from is
    /// the file just read.
    ///
    /// Keyed on the path rather than on the position in `feeds`, so a set
    /// reloaded against a different list of feeds cannot carry a zone forward
    /// under somebody else's policy. The policy is compared as well, because
    /// one file may be named twice at two policies (`TODO.md` #63j) and the
    /// override is baked into the indexed zone.
    fn kept(&self, feed: &Feed, digest: Option<FileDigest>) -> Option<Arc<PolicyZone>> {
        let digest = digest?;
        self.zones
            .iter()
            .find(|zone| {
                zone.policy == feed.policy
                    && zone
                        .read_from
                        .as_ref()
                        .is_some_and(|from| from.path == feed.path && from.digest == digest)
            })
            .cloned()
    }

    /// Zones already built, in the order they are consulted — for a caller
    /// that did not read them from files.
    pub fn from_zones(zones: Vec<PolicyZone>) -> PolicyZones {
        PolicyZones {
            zones: zones.into_iter().map(Arc::new).collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    pub fn zones(&self) -> &[Arc<PolicyZone>] {
        &self.zones
    }

    /// Whether one of these zones *is* the zone named — an exact origin, not a
    /// zone that would answer for the name.
    ///
    /// For deciding whether a NOTIFY is about a feed we hold (`TODO.md` #57).
    /// A linear scan because a resolver runs a handful of feeds and a map would
    /// be slower over one (`CLAUDE.md` §13); `NameRef`'s `PartialEq` is the
    /// ASCII fold (RFC 4343), so this cannot disagree with a zone map keyed on
    /// folded octets.
    pub fn carries(&self, zone: NameRef<'_>) -> bool {
        self.held(zone).is_some()
    }

    /// The feed with that origin, if this set holds it.
    ///
    /// What a transfer asks for: the version in force is the version an IXFR
    /// brings forward from (RFC 1995 §3), and it is already parsed and already
    /// in memory, so a refresh needs no second copy of a feed to hold a base
    /// against (`TODO.md` #57e).
    pub fn held(&self, zone: NameRef<'_>) -> Option<&PolicyZone> {
        self.zones
            .iter()
            .map(Arc::as_ref)
            .find(|held| held.origin() == zone)
    }

    /// The rewrite that applies before anything is resolved: the client's
    /// address, then the name it asked for, zone by zone in order.
    pub fn before_query(
        &self,
        client: IpAddr,
        qname: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<Rewrite> {
        for zone in &self.zones {
            if let Some(action) = zone.client_action(client, qname, qtype) {
                return Some(zone.rewrite(action, Trigger::ClientIp));
            }
            if let Some(action) = zone.qname_action(qname, qtype) {
                return Some(zone.rewrite(action, Trigger::Qname));
            }
        }
        None
    }

    /// Whether any zone has an NSDNAME or NSIP trigger.
    ///
    /// The resolver is handed a policy only when one does: the walk asks
    /// nothing, and the per-query [`DelegationPolicy`] is never built.
    pub fn watches_delegations(&self) -> bool {
        self.zones.iter().any(|zone| zone.watches_delegations())
    }

    /// The version of each zone that watches delegations, in the order they
    /// are consulted — what [`Reloaded::delegation_rules_changed`] compares.
    ///
    /// The serial is the zone's own claim to have changed: an RPZ is a DNS
    /// zone and a feed bumps it, which is also how a secondary decides whether
    /// to transfer one. A file edited without a bump is missed here exactly as
    /// a transfer would miss it. Coarse in the safe direction — a zone that
    /// carries one nameserver rule and a million QNAME rules reports a change
    /// when any of them moves.
    fn delegation_versions(&self) -> Vec<(Name, Option<Serial>)> {
        self.zones
            .iter()
            .filter(|zone| zone.watches_delegations())
            .map(|zone| (zone.origin().to_owned(), zone.zone.serial()))
            .collect()
    }

    /// One query's view of the nameserver triggers, to hand to the resolver.
    pub fn at_delegations(&self, qname: NameRef<'_>, qtype: Qtype) -> DelegationPolicy<'_> {
        DelegationPolicy {
            zones: self,
            qname: qname.to_owned(),
            qtype,
            hit: Mutex::new(None),
        }
    }

    /// The rewrite that applies to a delegation the resolver is about to
    /// follow: the names it was referred to, then the addresses those names
    /// stand for.
    ///
    /// NSDNAME before NSIP, which is the order `draft-vixie-dns-rpz-04` §2.2
    /// gives the two, and both after everything in [`PolicyZones::before_query`]
    /// because that pass runs before any resolution starts.
    pub fn on_delegation(
        &self,
        ns_names: &[Name],
        servers: &[IpAddr],
        qname: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<Rewrite> {
        for zone in &self.zones {
            for ns in ns_names {
                if let Some(action) = zone.nsdname_action(ns.as_ref(), qname, qtype) {
                    return Some(zone.rewrite(action, Trigger::Nsdname));
                }
            }
            for addr in servers {
                if let Some(action) = zone.ns_ip_action(*addr, qname, qtype) {
                    return Some(zone.rewrite(action, Trigger::Nsip));
                }
            }
        }
        None
    }

    /// The rewrite that applies to an answer already obtained: every address in
    /// it, against the response-IP triggers.
    pub fn on_answer(
        &self,
        answers: &[ResourceRecord],
        qname: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<Rewrite> {
        for zone in &self.zones {
            if zone.response_ip.is_empty() {
                continue;
            }
            for addr in answers.iter().filter_map(address_in) {
                if let Some(action) = zone.response_action(addr, qname, qtype) {
                    return Some(zone.rewrite(action, Trigger::ResponseIp));
                }
            }
        }
        None
    }
}

/// The policy zones in force, and the files they came from.
///
/// A feed is rewritten under a running resolver — by a cron job, or by an
/// `rdnsd` writing what it transferred — and until a reload re-reads it the
/// answer is a restart (`TODO.md` #57). The shape is the certificate store's
/// (`rdns_transport::tls::CertificateStore`): the paths, a current value behind
/// a lock, and a `reload` that leaves the old one in force if the new one does
/// not parse.
///
/// One query reads [`PolicyStore::in_force`] once and decides by that snapshot,
/// which is why an `Arc` is handed out rather than a guard: the nameserver
/// triggers are consulted across a resolution a dozen round trips long, and no
/// lock may be held over it (`CLAUDE.md` §9).
#[derive(Debug)]
pub struct PolicyStore {
    feeds: Vec<Feed>,
    current: RwLock<Arc<PolicyZones>>,
    /// Zones this process wrote to a feed's file and has not installed yet —
    /// [`PolicyStore::offer`].
    offered: Mutex<Vec<Arc<PolicyZone>>>,
}

impl PolicyStore {
    /// Read every feed, or fail without installing any of them.
    pub fn load(feeds: &[Feed]) -> ConfigResult<Arc<PolicyStore>> {
        let zones = PolicyZones::load(feeds)?;
        Ok(Arc::new(PolicyStore {
            feeds: feeds.to_vec(),
            current: RwLock::new(Arc::new(zones)),
            offered: Mutex::new(Vec::new()),
        }))
    }

    /// A store over zones that came from somewhere other than a file, for a
    /// caller that has already built them. Reloading one re-reads nothing.
    pub fn in_memory(zones: PolicyZones) -> Arc<PolicyStore> {
        Arc::new(PolicyStore {
            feeds: Vec::new(),
            current: RwLock::new(Arc::new(zones)),
            offered: Mutex::new(Vec::new()),
        })
    }

    /// Index a zone this process just wrote, and keep it for the next reload
    /// to install without parsing the file back — `TODO.md` #71f.
    ///
    /// The [`Written`] is the write: only [`crate::zone_writer::write_zone_text`]
    /// makes one, so a caller cannot offer bytes it did not put on disk or
    /// offer them before it did. That rule used to be this sentence — "the
    /// caller writes `text` to `path` first and passes the same bytes here" —
    /// with nothing making it true (`TODO.md` #104, `CLAUDE.md` §17).
    ///
    /// A reload still reads every file, and takes this zone only if the file's
    /// bytes are still the bytes written here, so a feed somebody else rewrote
    /// in between is parsed as it would have been: the digest is the whole
    /// test and it is the same one `rdnsd`'s UPDATE path applies to a zone it
    /// wrote (`TODO.md` #64b, `CLAUDE.md` §7).
    ///
    /// **Blocking**: indexing a million-rule feed is ~40 ms, so this belongs
    /// where the write does, off the workers (`CLAUDE.md` §9).
    ///
    /// The feed's policy comes from the configured list rather than from the
    /// caller — a zone offered under the wrong override would answer a query
    /// differently than the same file read back (§15's rule about two sources
    /// for one setting).
    pub fn offer(&self, written: &Written, zone: Zone) -> ConfigResult<()> {
        let path = written.path();
        let Some(feed) = self.feeds.iter().find(|feed| feed.path == path) else {
            // Refused rather than dropped: writing a policy zone to a path no
            // feed reads is a configuration nobody gets an answer from, and a
            // silent `Ok` here is the reload quietly costing what this exists
            // to save (`CLAUDE.md` §4).
            return Err(ConfigError::new(format!(
                "no policy feed reads {}, so a zone written there is never in force",
                path.display()
            )));
        };
        let indexed = Arc::new(PolicyZone::from_written(zone, feed.policy, written)?);
        let mut offered = match self.offered.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        // One per path and policy: an older offer for the same feed is a zone
        // the file no longer holds.
        offered.retain(|zone| !zone.was_read_from(path) || zone.policy != feed.policy);
        offered.push(indexed);
        Ok(())
    }

    /// Everything offered since the last reload, leaving none behind.
    fn take_offered(&self) -> PolicyZones {
        let mut offered = match self.offered.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        PolicyZones {
            zones: std::mem::take(&mut offered),
        }
    }

    /// Whether any feed was named, and so whether a reload has anything to do.
    pub fn is_configured(&self) -> bool {
        !self.feeds.is_empty()
    }

    /// The set to decide one query by.
    pub fn in_force(&self) -> Arc<PolicyZones> {
        // A poisoned lock still holds a whole, valid set: the only thing done
        // under this lock is one `Arc` assignment, which cannot leave a torn
        // value behind. Recovering keeps the policy in force, where `unwrap`
        // would take the resolver off the air and a default would silently lift
        // every block (`CLAUDE.md` §4, §6).
        match self.current.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Re-read every file and install the result.
    ///
    /// All-or-nothing, as at startup: a feed that will not parse must not leave
    /// the resolver enforcing a policy shorter than the one configured, so the
    /// previous set stays in force and the caller is told which file was wrong.
    pub fn reload(&self) -> ConfigResult<Reloaded> {
        // The set in force, read out before the work and not under a guard: a
        // feed is seconds to parse and no lock may be held over that
        // (`CLAUDE.md` §9). Two reloads at once would both read it and the
        // second to finish would win, which is what happens today as well; the
        // resolver's reload task runs one at a time.
        let held = self.in_force();
        // Taken, not borrowed: a zone offered for a file that has since changed
        // is a zone nothing can use, and holding a million-rule feed against
        // the chance of a later match is the memory this saves. A reload that
        // fails costs the next one a parse.
        let offered = self.take_offered();
        let zones = Arc::new(PolicyZones::reload(&self.feeds, &held, &offered)?);
        let new: Vec<&Arc<PolicyZone>> = zones
            .zones()
            .iter()
            .filter(|zone| !held.zones().iter().any(|was| Arc::ptr_eq(zone, was)))
            .collect();
        let installed = new
            .iter()
            .filter(|zone| offered.zones().iter().any(|was| Arc::ptr_eq(zone, was)))
            .count();
        let reread = new.len() - installed;
        let mut guard = match self.current.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let delegation_rules_changed = zones.delegation_versions() != guard.delegation_versions();
        *guard = zones.clone();
        Ok(Reloaded {
            zones,
            delegation_rules_changed,
            reread,
            installed,
        })
    }
}

/// What a reload installed, and the one thing a caller holding a cache has to
/// know about it.
#[derive(Debug)]
pub struct Reloaded {
    /// The set now in force.
    pub zones: Arc<PolicyZones>,
    /// How many feeds were parsed again, the rest having been kept whole
    /// (`TODO.md` #71b).
    ///
    /// Logged, because a reload that skips work has to be able to say it did:
    /// an operator whose edit did not register sees "0 of 3" and knows to look
    /// at the file rather than at the rule (`CLAUDE.md` §14).
    pub reread: usize,
    /// How many feeds came from a zone this process had written and kept
    /// (`TODO.md` #71f) — changed, but not parsed again.
    ///
    /// Counted apart from `reread` because the two differ only in cost: a
    /// transferred feed that installed without a parse *did* change, and a log
    /// line that said "0 of 3 changed" would send an operator to look at a file
    /// that is in force.
    pub installed: usize,
    /// Whether any zone that has something to say about a delegation is at a
    /// different version than the one it replaced.
    ///
    /// A reload's one obligation to an answer cache. A QNAME or client-IP rule
    /// is consulted before every cache and a response-IP rule is applied to
    /// what leaves, so a new one of either is in force for the next query
    /// whatever is held. A nameserver rule can only be asked while a delegation
    /// is being walked, so an answer already cached is never offered to it and
    /// outlives the rule by its TTL (`TODO.md` #56, #57).
    pub delegation_rules_changed: bool,
}

/// One query's nameserver triggers, as the resolver consults them.
///
/// Built per query and only when [`PolicyZones::watches_delegations`] says
/// there is something to consult. The resolver holds it by shared reference
/// across the walk, so the match it found is behind a `Mutex` — locked twice
/// per delegation and never across an await.
pub struct DelegationPolicy<'a> {
    zones: &'a PolicyZones,
    qname: Name,
    qtype: Qtype,
    hit: Mutex<Option<Rewrite>>,
}

impl DelegationPolicy<'_> {
    /// What stopped the resolution, if anything did.
    pub fn matched(&self) -> Option<Rewrite> {
        self.hit.lock().ok()?.take()
    }
}

impl NameserverPolicy for DelegationPolicy<'_> {
    fn allows(&self, ns_names: &[Name], servers: &[SocketAddr]) -> bool {
        // The port is this resolver's business, not the policy's: an NSIP rule
        // is about the host.
        let addrs: Vec<IpAddr> = servers.iter().map(SocketAddr::ip).collect();
        let Some(rewrite) =
            self.zones
                .on_delegation(ns_names, &addrs, self.qname.as_ref(), self.qtype)
        else {
            return true;
        };
        // A passthru is a match that changes nothing, so the resolution is
        // exactly what it would have been — including its cache entry. Stopping
        // for one would turn the exception into the block it exists to carve
        // out of.
        if rewrite.action == Action::Passthru {
            return true;
        }
        let Ok(mut hit) = self.hit.lock() else {
            // A poisoned lock means a panic already happened here. Refuse: the
            // policy said no and the caller will find nothing recorded, which
            // is a SERVFAIL rather than an answer the operator meant to block.
            return false;
        };
        *hit = Some(rewrite);
        false
    }
}

/// The address a record carries, for the response-IP triggers.
fn address_in(record: &ResourceRecord) -> Option<IpAddr> {
    match record.rdata.parse() {
        Ok(ParsedRecord::A(v4)) => Some(IpAddr::V4(v4)),
        Ok(ParsedRecord::AAAA(v6)) => Some(IpAddr::V6(v6)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_records::nm;
    use crate::testutil::ScratchDir;
    use crate::zone::parse_zone_file;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const ORIGIN: &str = "rpz.invalid.";

    /// One zone carrying every trigger shape this module reads, so a test of one
    /// of them is also a test that the others did not swallow it.
    const POLICY: &str = "\
$TTL 60
@                       IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. 1 3600 600 86400 60
@                       IN NS  localhost.
evil.example.com        IN CNAME .
*.bad.example.com       IN CNAME .
ok.bad.example.com      IN CNAME rpz-passthru.
nodata.example.com      IN CNAME *.
gone.example.com        IN CNAME rpz-drop.
tcp.example.com         IN CNAME rpz-tcp-only.
walled.example.com      IN A     192.0.2.10
elsewhere.example.com   IN CNAME landing.example.net.
8.0.0.0.127.rpz-client-ip   IN CNAME .
32.1.0.0.127.rpz-client-ip  IN CNAME rpz-passthru.
24.0.2.0.198.rpz-ip         IN CNAME .
32.zz.db8.2001.rpz-ip       IN CNAME .
ns.evil.example.com.rpz-nsdname IN CNAME .
*.hoster.example.net.rpz-nsdname IN CNAME .
good.hoster.example.net.rpz-nsdname IN CNAME rpz-passthru.
32.13.2.0.192.rpz-nsip      IN CNAME .
";

    /// Indexing address triggers must not be quadratic in their number.
    ///
    /// A ratio, not a wall-clock floor: doubling the rules must roughly double
    /// the work, which is machine-independent where a time limit is a coin toss
    /// (`CLAUDE.md` §10). The `Vec` scanned per record read 4x per doubling —
    /// 92.8 ms at 8k rules and 400.3 ms at 16k — and fails this at 3x with room
    /// to spare, while the set is at ~2x.
    ///
    /// The trigger lists are what the module's own comment calls "tens of
    /// entries". Nothing enforces that, and an IP blocklist delivered as RPZ is
    /// all `rpz-ip` (`TODO.md` #62b).
    #[test]
    fn indexing_address_triggers_does_not_grow_quadratically() {
        fn feed(rules: usize) -> String {
            let mut text = String::from(
                "$TTL 60\n\
                 @ IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. 1 3600 600 86400 60\n\
                 @ IN NS localhost.\n",
            );
            for i in 0..rules {
                let (a, b, c) = ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
                text.push_str(&format!("32.{c}.{b}.{a}.10.rpz-ip IN CNAME .\n"));
            }
            text
        }
        fn index(rules: usize) -> std::time::Duration {
            let zone = parse_zone_file(&feed(rules), ORIGIN).expect("parses");
            let start = std::time::Instant::now();
            let indexed = PolicyZone::new(zone, PolicyOverride::Given).expect("indexes");
            let took = start.elapsed();
            assert_eq!(
                indexed.trigger_counts()[2],
                rules,
                "every rule is a trigger"
            );
            took
        }

        let small = index(8_000);
        let large = index(16_000);
        assert!(
            large < small * 3,
            "twice the rules must not cost four times the work: \
             {small:?} at 8k against {large:?} at 16k"
        );
    }

    /// Answering a query must not cost more because the feed is bigger.
    ///
    /// A ratio, not a wall-clock floor (`CLAUDE.md` §10): ten times the rules
    /// must not cost ten times the lookup. The scan this replaced was linear
    /// in them — 2.81 µs at 1 000 rules, 28.1 µs at 10 000 and 144.6 µs at
    /// 50 000 in release, on the miss path every ordinary query pays — and
    /// fails this by an order of magnitude, where the flattened index reads
    /// 5, 7 and 7 ns (`TODO.md` #62a).
    #[test]
    fn a_query_costs_the_same_however_many_address_rules_the_feed_holds() {
        fn feed(rules: usize) -> String {
            let mut text = String::from(
                "$TTL 60\n\
                 @ IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. 1 3600 600 86400 60\n\
                 @ IN NS localhost.\n",
            );
            for i in 0..rules {
                let (a, b, c) = ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
                text.push_str(&format!("32.{c}.{b}.{a}.10.rpz-client-ip IN CNAME .\n"));
            }
            text
        }
        fn per_lookup(rules: usize) -> std::time::Duration {
            let zone = parse_zone_file(&feed(rules), ORIGIN).expect("parses");
            let indexed = PolicyZone::new(zone, PolicyOverride::Given).expect("indexes");
            assert_eq!(
                indexed.trigger_counts()[1],
                rules,
                "every rule is a trigger"
            );

            // Addresses no rule covers. The miss is the case to measure: a hit
            // stops at whichever rule matched, so a scan looks fast whenever
            // the answer is near the front of it.
            let miss: Vec<IpAddr> = (0..64)
                .map(|i| IpAddr::V4(Ipv4Addr::new(203, 0, 113, i)))
                .collect();
            let qname = nm("www.example.com.");
            let qtype = Qtype::of(rt::A);
            let reps = 200;

            let mut matched = 0usize;
            let start = std::time::Instant::now();
            for _ in 0..reps {
                for addr in &miss {
                    let addr = std::hint::black_box(*addr);
                    if indexed.client_action(addr, qname.as_ref(), qtype).is_some() {
                        matched += 1;
                    }
                }
            }
            let took = start.elapsed();
            assert_eq!(matched, 0, "203.0.113.0/24 is not in the feed");
            took / (reps * miss.len()) as u32
        }

        let small = per_lookup(1_000);
        let large = per_lookup(10_000);
        // `--nocapture` is how the two figures are read; the assertion is the
        // ratio, which is the part that does not depend on the machine.
        println!("client-IP lookup: {small:?} at 1k rules, {large:?} at 10k");
        assert!(
            large < small * 4,
            "ten times the rules must not cost ten times the lookup: \
             {small:?} at 1k against {large:?} at 10k"
        );
    }

    fn policy_zones(policy: PolicyOverride) -> PolicyZones {
        let zone = parse_zone_file(POLICY, ORIGIN).expect("the policy zone parses");
        PolicyZones {
            zones: vec![Arc::new(PolicyZone::new(zone, policy).expect("it indexes"))],
        }
    }

    fn zones() -> PolicyZones {
        policy_zones(PolicyOverride::Given)
    }

    fn a_query(name: &str) -> (Name, Qtype) {
        (nm(name), Qtype::of(rt::A))
    }

    fn client() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200))
    }

    fn action_for(zones: &PolicyZones, name: &str, qtype: Qtype) -> Option<Action> {
        zones
            .before_query(client(), nm(name).as_ref(), qtype)
            .map(|rewrite| rewrite.action)
    }

    /// `CNAME .` is the whole of "this name does not exist".
    #[test]
    fn a_cname_to_the_root_is_nxdomain() {
        let (name, qtype) = a_query("evil.example.com.");
        let rewrite = zones()
            .before_query(client(), name.as_ref(), qtype)
            .expect("the trigger matches");
        assert_eq!(rewrite.action, Action::Nxdomain);
        assert_eq!(rewrite.trigger, Trigger::Qname);
        assert_eq!(rewrite.zone, nm(ORIGIN));
        assert!(
            rewrite.soa.is_some(),
            "a negative rewrite owes an SOA or it cannot be cached (RFC 2308 §5)"
        );
    }

    /// A name nothing in the zone mentions is the ordinary case, and the one
    /// every query pays for.
    #[test]
    fn a_name_with_no_trigger_is_not_rewritten() {
        assert_eq!(
            action_for(&zones(), "www.example.com.", Qtype::of(rt::A)),
            None
        );
    }

    /// The trigger name is the QNAME under the policy origin, so a wildcard
    /// trigger is an ordinary zone wildcard: it reaches the names *below*
    /// `bad.example.com.` and not the name itself (RFC 4592 §2.1.1).
    #[test]
    fn a_wildcard_trigger_covers_the_subtree_and_not_its_own_name() {
        let zones = zones();
        assert_eq!(
            action_for(&zones, "anything.bad.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain)
        );
        assert_eq!(
            action_for(&zones, "deeper.anything.bad.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain)
        );
        assert_eq!(
            action_for(&zones, "bad.example.com.", Qtype::of(rt::A)),
            None,
            "the wildcard's own name has no records of its own"
        );
    }

    /// An exact trigger shadows the wildcard above it, which is how an exception
    /// is carved out of a feed's blanket rule.
    #[test]
    fn an_exact_passthru_shadows_the_wildcard_above_it() {
        assert_eq!(
            action_for(&zones(), "ok.bad.example.com.", Qtype::of(rt::A)),
            Some(Action::Passthru)
        );
    }

    #[test]
    fn the_four_other_verbs_read_as_themselves() {
        let zones = zones();
        assert_eq!(
            action_for(&zones, "nodata.example.com.", Qtype::of(rt::A)),
            Some(Action::Nodata)
        );
        assert_eq!(
            action_for(&zones, "gone.example.com.", Qtype::of(rt::A)),
            Some(Action::Drop)
        );
        assert_eq!(
            action_for(&zones, "tcp.example.com.", Qtype::of(rt::A)),
            Some(Action::TcpOnly)
        );
    }

    /// Local data answers under the name that was asked for, not under the
    /// trigger: a client comparing the owner name against its question would
    /// otherwise reject the answer.
    #[test]
    fn local_data_is_rewritten_to_the_name_asked_for() {
        let Some(Action::LocalData(records)) =
            action_for(&zones(), "walled.example.com.", Qtype::of(rt::A))
        else {
            panic!("the A trigger answers");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, nm("walled.example.com."));
        assert_eq!(
            records[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 10))
        );
    }

    /// A trigger holding only an A is a NODATA for every other type — the same
    /// answer the name would get from a zone that held it.
    #[test]
    fn local_data_of_another_type_is_nodata() {
        assert_eq!(
            action_for(&zones(), "walled.example.com.", Qtype::of(rt::AAAA)),
            Some(Action::Nodata)
        );
    }

    /// A CNAME that is not one of the five verbs is a redirect, and it answers
    /// whatever the QTYPE was: a CNAME is the answer to any question.
    #[test]
    fn a_cname_to_a_real_name_answers_any_type() {
        for qtype in [Qtype::of(rt::A), Qtype::of(rt::AAAA), Qtype::of(rt::MX)] {
            let Some(Action::LocalData(records)) =
                action_for(&zones(), "elsewhere.example.com.", qtype)
            else {
                panic!("the redirect answers {qtype}");
            };
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].rdata.parse().unwrap(),
                ParsedRecord::CNAME(nm("landing.example.net."))
            );
        }
    }

    /// The client's own address is a trigger, and the longest prefix wins — so
    /// one host is exempted from a rule covering the network it is on.
    #[test]
    fn a_client_ip_trigger_matches_by_longest_prefix() {
        let zones = zones();
        let blocked = zones.before_query(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)),
            nm("www.example.com.").as_ref(),
            Qtype::of(rt::A),
        );
        assert_eq!(blocked.as_ref().map(|r| &r.action), Some(&Action::Nxdomain));
        assert_eq!(blocked.unwrap().trigger, Trigger::ClientIp);

        let exempt = zones.before_query(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            nm("www.example.com.").as_ref(),
            Qtype::of(rt::A),
        );
        assert_eq!(
            exempt.map(|r| r.action),
            Some(Action::Passthru),
            "/32 is more specific than the /8 it sits inside"
        );
    }

    /// A rule covering the whole address space is legal, and `::/0` is the
    /// edge the flattening arithmetic has to survive: its span ends at
    /// `u128::MAX`, where advancing past the last span would wrap to the
    /// bottom of the space instead.
    #[test]
    fn a_rule_covering_every_address_still_yields_to_a_longer_prefix() {
        const EVERYTHING: &str = "\
$TTL 60
@                            IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. 1 3600 600 86400 60
@                            IN NS  localhost.
0.0.0.0.0.rpz-client-ip      IN CNAME .
32.1.0.0.127.rpz-client-ip   IN CNAME rpz-passthru.
0.zz.rpz-client-ip           IN CNAME .
64.zz.db8.2001.rpz-client-ip IN CNAME rpz-passthru.
";
        let zone = parse_zone_file(EVERYTHING, ORIGIN).expect("the policy zone parses");
        let zones = PolicyZones {
            zones: vec![Arc::new(
                PolicyZone::new(zone, PolicyOverride::Given).expect("it indexes"),
            )],
        };
        let action = |addr: IpAddr| {
            zones
                .before_query(addr, nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .map(|r| r.action)
        };
        for (addr, want) in [
            (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), Action::Nxdomain),
            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), Action::Passthru),
            (
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
                Action::Nxdomain,
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                Action::Passthru,
            ),
        ] {
            assert_eq!(action(addr), Some(want.clone()), "{addr} is {want:?}");
        }
    }

    /// A v4 rule must not match a v4-mapped v6 client, which would be a way
    /// around the list — the rule `security::TransferAcl` already holds.
    #[test]
    fn a_v4_client_rule_does_not_match_a_mapped_v6_client() {
        let mapped = IpAddr::V6(Ipv4Addr::new(127, 0, 0, 9).to_ipv6_mapped());
        assert!(zones()
            .before_query(mapped, nm("www.example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
    }

    /// The address in an answer is a trigger too: a name nobody blocked that
    /// resolves into blocked space.
    #[test]
    fn a_response_ip_trigger_matches_an_address_in_the_answer() {
        let zones = zones();
        let answer = vec![ResourceRecord {
            name: nm("www.example.com."),
            class: crate::Class::new(1),
            ttl: crate::Ttl::from_secs(60),
            rdata: crate::RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(198, 0, 2, 7)))
                .unwrap(),
        }];
        let rewrite = zones
            .on_answer(&answer, nm("www.example.com.").as_ref(), Qtype::of(rt::A))
            .expect("198.0.2.0/24 is a trigger");
        assert_eq!(rewrite.action, Action::Nxdomain);
        assert_eq!(rewrite.trigger, Trigger::ResponseIp);
    }

    #[test]
    fn a_v6_response_ip_trigger_reads_its_zz() {
        let zones = zones();
        let answer = vec![ResourceRecord {
            name: nm("www.example.com."),
            class: crate::Class::new(1),
            ttl: crate::Ttl::from_secs(60),
            rdata: crate::RecordData::from_parsed(&ParsedRecord::AAAA(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
            )))
            .unwrap(),
        }];
        assert!(zones
            .on_answer(
                &answer,
                nm("www.example.com.").as_ref(),
                Qtype::of(rt::AAAA)
            )
            .is_some());
    }

    /// `zz` is `::`: the longest run of zero words, wherever it falls.
    #[test]
    fn an_address_trigger_reads_both_families() {
        let cases: [(&[&[u8]], IpAddr, u8); 4] = [
            (
                &[b"8", b"0", b"0", b"0", b"127"],
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                8,
            ),
            (
                &[b"32", b"zz", b"db8", b"2001"],
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                32,
            ),
            (
                &[b"128", b"1", b"zz", b"db8", b"2001"],
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                128,
            ),
            (
                &[b"128", b"1", b"0", b"0", b"0", b"0", b"0", b"0", b"0"],
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                128,
            ),
        ];
        for (labels, addr, prefix) in cases {
            assert_eq!(
                parse_ip_trigger(labels),
                Ok((addr, prefix)),
                "{labels:?} is {addr}/{prefix}"
            );
        }
    }

    #[test]
    fn a_malformed_address_trigger_is_refused_at_load() {
        for labels in [
            &[b"32".as_slice(), b"zz", b"zz", b"2001"][..],
            &[b"nine".as_slice(), b"0", b"0", b"0", b"127"][..],
            &[b"129".as_slice(), b"zz", b"db8", b"2001"][..],
            &[b"64".as_slice(), b"db8", b"2001"][..],
        ] {
            assert!(
                parse_ip_trigger(labels).is_err(),
                "{labels:?} is not an address"
            );
        }
    }

    /// A query for a name ending in `rpz-ip` builds a trigger name inside the
    /// address subtree, where an address rule is waiting. It is not a QNAME
    /// trigger and must not match one.
    #[test]
    fn a_query_name_inside_an_address_subtree_is_not_a_qname_trigger() {
        assert_eq!(
            action_for(&zones(), "24.0.2.0.198.rpz-ip.", Qtype::of(rt::A)),
            None
        );
    }

    /// The zone's own action is what `given` means; every other policy replaces
    /// it, and `disabled` keeps the configuration while matching nothing.
    #[test]
    fn a_policy_override_replaces_every_action_in_the_zone() {
        let overridden = policy_zones(PolicyOverride::Nodata);
        assert_eq!(
            action_for(&overridden, "evil.example.com.", Qtype::of(rt::A)),
            Some(Action::Nodata),
            "the zone says NXDOMAIN and the policy says otherwise"
        );
        assert_eq!(
            action_for(&overridden, "ok.bad.example.com.", Qtype::of(rt::A)),
            Some(Action::Nodata),
            "a passthru in the zone is an action like any other"
        );

        let off = policy_zones(PolicyOverride::Disabled);
        assert_eq!(
            action_for(&off, "evil.example.com.", Qtype::of(rt::A)),
            None
        );
    }

    /// The banner counts each trigger kind, so the feed that loaded and the
    /// feed the operator meant to load are two different pictures.
    #[test]
    fn every_trigger_kind_is_counted_for_the_banner() {
        let zones = zones();
        let [qname, client_ip, response_ip, nsdname, nsip] = zones.zones()[0].trigger_counts();
        assert_eq!(
            (client_ip, response_ip, nsdname, nsip),
            (2, 2, 3, 1),
            "the four indexed kinds are counted exactly"
        );
        // Not a rule count: the apex SOA and NS are in it, which is why the
        // banner calls the first number what is left over.
        assert_eq!(qname, zones.zones()[0].records() - 8);
    }

    /// A rewrite to NXDOMAIN needs the zone's SOA, so a file without one is a
    /// configuration error rather than a policy that half works.
    #[test]
    fn a_policy_zone_without_an_soa_is_refused() {
        let zone = parse_zone_file("evil.example.com IN CNAME .\n", ORIGIN).unwrap();
        let err = PolicyZone::new(zone, PolicyOverride::Given).unwrap_err();
        assert!(err.to_string().contains("no SOA"), "{err}");
    }

    /// Zones are consulted in order: the first with anything to say wins, which
    /// is how a local exception list sits in front of a bought feed.
    #[test]
    fn the_first_zone_that_matches_wins() {
        const LOCAL: &str = "\
$TTL 60
@                IN SOA ns.local.invalid. hostmaster.local.invalid. 1 3600 600 86400 60
evil.example.com IN CNAME rpz-passthru.
";
        let local = parse_zone_file(LOCAL, "local.invalid.").unwrap();
        let feed = parse_zone_file(POLICY, ORIGIN).unwrap();
        let zones = PolicyZones {
            zones: vec![
                Arc::new(PolicyZone::new(local, PolicyOverride::Given).unwrap()),
                Arc::new(PolicyZone::new(feed, PolicyOverride::Given).unwrap()),
            ],
        };
        assert_eq!(
            action_for(&zones, "evil.example.com.", Qtype::of(rt::A)),
            Some(Action::Passthru),
            "the local zone is first and says to let it through"
        );
    }

    fn ns(names: &[&str]) -> Vec<Name> {
        names.iter().map(|n| nm(n)).collect()
    }

    fn addrs(text: &[&str]) -> Vec<IpAddr> {
        text.iter().map(|a| a.parse().unwrap()).collect()
    }

    /// The trigger is the nameserver's name under `rpz-nsdname.<origin>`, and
    /// what it rewrites is the *query*: the client asked about a name nothing
    /// in the feed mentions, and it is blocked for the company it keeps.
    #[test]
    fn a_nameserver_name_is_a_trigger() {
        let zones = zones();
        let rewrite = zones
            .on_delegation(
                &ns(&["ns1.example.com.", "ns.evil.example.com."]),
                &addrs(&["203.0.113.1"]),
                nm("www.unlisted.test.").as_ref(),
                Qtype::of(rt::A),
            )
            .expect("the second nameserver is listed");
        assert_eq!(rewrite.action, Action::Nxdomain);
        assert_eq!(rewrite.trigger, Trigger::Nsdname);
        assert_eq!(rewrite.zone, nm(ORIGIN));
    }

    /// A nameserver's *address*, which is the trigger a feed reaches for when
    /// the operator renames servers faster than they renumber them.
    #[test]
    fn a_nameserver_address_is_a_trigger() {
        let zones = zones();
        let rewrite = zones
            .on_delegation(
                &ns(&["ns1.unlisted.test."]),
                &addrs(&["203.0.113.1", "192.0.2.13"]),
                nm("www.unlisted.test.").as_ref(),
                Qtype::of(rt::A),
            )
            .expect("the second address is listed");
        assert_eq!(rewrite.action, Action::Nxdomain);
        assert_eq!(rewrite.trigger, Trigger::Nsip);
    }

    /// Names before addresses, which is the order `draft-vixie-dns-rpz-04`
    /// gives them — visible only when one delegation matches both.
    #[test]
    fn a_name_match_is_reported_before_an_address_match() {
        let zones = zones();
        let rewrite = zones
            .on_delegation(
                &ns(&["ns.evil.example.com."]),
                &addrs(&["192.0.2.13"]),
                nm("www.unlisted.test.").as_ref(),
                Qtype::of(rt::A),
            )
            .unwrap();
        assert_eq!(rewrite.trigger, Trigger::Nsdname);
    }

    /// A delegation nothing in the feed names costs a lookup and no rewrite.
    #[test]
    fn an_unlisted_delegation_is_not_rewritten() {
        assert!(zones()
            .on_delegation(
                &ns(&["ns1.example.com."]),
                &addrs(&["203.0.113.1"]),
                nm("www.unlisted.test.").as_ref(),
                Qtype::of(rt::A),
            )
            .is_none());
    }

    /// A wildcard NSDNAME rule is an ordinary zone wildcard, and an exact rule
    /// under it wins — which is how one customer is carved out of a hoster.
    #[test]
    fn a_wildcard_nameserver_rule_has_exceptions() {
        let zones = zones();
        let blocked = zones.on_delegation(
            &ns(&["bad.hoster.example.net."]),
            &[],
            nm("www.unlisted.test.").as_ref(),
            Qtype::of(rt::A),
        );
        assert_eq!(blocked.map(|r| r.action), Some(Action::Nxdomain));
        let allowed = zones.on_delegation(
            &ns(&["good.hoster.example.net."]),
            &[],
            nm("www.unlisted.test.").as_ref(),
            Qtype::of(rt::A),
        );
        assert_eq!(allowed.map(|r| r.action), Some(Action::Passthru));
    }

    /// A zone with no nameserver rule is never asked: the resolver is handed no
    /// policy at all, so a feed of QNAME triggers costs a walk nothing.
    #[test]
    fn only_a_zone_with_a_nameserver_rule_watches_delegations() {
        const PLAIN: &str = "$TTL 60
@                IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. 1 3600 600 86400 60
evil.example.com IN CNAME .
";
        assert!(zones().watches_delegations());
        let plain = parse_zone_file(PLAIN, ORIGIN).unwrap();
        let plain =
            PolicyZones::from_zones(vec![PolicyZone::new(plain, PolicyOverride::Given).unwrap()]);
        assert!(!plain.watches_delegations());
    }

    /// What the resolver sees: a refusal that records the rewrite, and a
    /// passthru that does not stop the walk — stopping for one would turn the
    /// exception into the rule it is carved out of.
    #[test]
    fn the_resolver_is_told_to_stop_for_everything_but_a_passthru() {
        let zones = zones();
        let qtype = Qtype::of(rt::A);

        let watch = zones.at_delegations(nm("www.unlisted.test.").as_ref(), qtype);
        assert!(!watch.allows(&ns(&["ns.evil.example.com."]), &[]));
        let rewrite = watch.matched().expect("the refusal recorded what matched");
        assert_eq!(rewrite.trigger, Trigger::Nsdname);
        assert!(
            watch.matched().is_none(),
            "the match is taken, so a second read cannot replay it"
        );

        let watch = zones.at_delegations(nm("www.unlisted.test.").as_ref(), qtype);
        assert!(watch.allows(&ns(&["good.hoster.example.net."]), &[]));
        assert!(watch.matched().is_none(), "a passthru records nothing");
    }

    /// A nameserver called `something.rpz-ip.` must not build a trigger name
    /// inside the address subtree, for the reason `qname_action` guards the
    /// same shape: `24.0.2.0.198.rpz-ip` would answer for it.
    #[test]
    fn a_nameserver_named_like_a_subtree_matches_nothing() {
        assert!(zones()
            .on_delegation(
                &ns(&["24.0.2.0.198.rpz-ip."]),
                &[],
                nm("www.unlisted.test.").as_ref(),
                Qtype::of(rt::A),
            )
            .is_none());
    }

    /// A feed, parameterised by the two things a reload turns on: the serial
    /// the zone claims to be at, and whether it has anything to say about a
    /// delegation.
    fn feed(serial: u32, blocked: &str, nsdname: Option<&str>) -> String {
        let mut text = format!(
            "$TTL 60\n\
             @ IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. {serial} 3600 600 86400 60\n\
             @ IN NS localhost.\n\
             {blocked} IN CNAME .\n"
        );
        if let Some(ns) = nsdname {
            text.push_str(&format!("{ns}.rpz-nsdname IN CNAME .\n"));
        }
        text
    }

    /// The point of #57: a feed rewritten under a running resolver is read
    /// again, and the rule that arrived is in force for the next query.
    ///
    /// Fails against the shape this replaced, where the zones were read once
    /// into `Resolving` and the only way to change them was a restart.
    #[test]
    fn a_reload_reads_the_file_again() {
        let dir = ScratchDir::new("rpz-reload");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("it loads");
        assert_eq!(
            action_for(&store.in_force(), "second.example.com.", Qtype::of(rt::A)),
            None
        );

        std::fs::write(&path, feed(2, "second.example.com", None)).expect("rewrite");
        let reloaded = store.reload().expect("it re-reads");
        assert_eq!(
            action_for(&store.in_force(), "second.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain)
        );
        assert_eq!(
            action_for(&store.in_force(), "first.example.com.", Qtype::of(rt::A)),
            None,
            "a rule the feed dropped is a rule that stopped being enforced"
        );
        assert!(
            !reloaded.delegation_rules_changed,
            "neither version had a nameserver trigger, so nothing held was bypassing one"
        );
    }

    /// A policy per feed, which is what a set of them is for: the new feed is
    /// measured in `passthru` while the enforced one stays enforced
    /// (`TODO.md` #63j).
    ///
    /// Fails against the shape this replaced, where `load` took one policy for
    /// the set and both rules would read as `Passthru`. The match path is
    /// unchanged — `PolicyZone` has held its own policy since it was written,
    /// and `action_at` has always applied that one.
    #[test]
    fn each_feed_keeps_the_policy_it_was_loaded_with() {
        let dir = ScratchDir::new("rpz-per-feed");
        let enforced = dir.write("enforced.zone", &feed(1, "blocked.example.com", None));
        let measured = dir.write("measured.zone", &feed(1, "candidate.example.com", None));
        let store = PolicyStore::load(&[
            Feed::new(enforced, PolicyOverride::Given),
            Feed::new(measured, PolicyOverride::Passthru),
        ])
        .expect("both load");

        let in_force = store.in_force();
        assert_eq!(
            action_for(&in_force, "blocked.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain)
        );
        assert_eq!(
            action_for(&in_force, "candidate.example.com.", Qtype::of(rt::A)),
            Some(Action::Passthru),
            "the feed being measured must not block while the other one does"
        );

        // And a reload keeps them apart, which is the half that would drift:
        // the store carries the feeds rather than one policy for the set.
        std::fs::write(
            dir.path().join("measured.zone"),
            feed(2, "another.example.com", None),
        )
        .expect("rewrite");
        let reloaded = store.reload().expect("it re-reads");
        assert_eq!(
            action_for(&reloaded.zones, "another.example.com.", Qtype::of(rt::A)),
            Some(Action::Passthru)
        );
    }

    /// All-or-nothing, as at startup: one unparseable file out of two must not
    /// leave the resolver enforcing half the policy (`CLAUDE.md` §4).
    #[test]
    fn a_feed_that_will_not_parse_leaves_the_previous_ones_in_force() {
        let dir = ScratchDir::new("rpz-reload-broken");
        let first = dir.write("first.zone", &feed(1, "first.example.com", None));
        let second = dir.write("second.zone", &feed(1, "second.example.com", None));
        let store = PolicyStore::load(&[
            Feed::new(first.clone(), PolicyOverride::Given),
            Feed::new(second.clone(), PolicyOverride::Given),
        ])
        .expect("both load");

        // The first file is good and the second is not, so a loader that
        // installed as it went would leave the new first rule in force.
        std::fs::write(&first, feed(2, "third.example.com", None)).expect("rewrite");
        std::fs::write(&second, "this is not a zone file\n").expect("rewrite");
        assert!(store.reload().is_err());

        let in_force = store.in_force();
        assert_eq!(
            action_for(&in_force, "first.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain)
        );
        assert_eq!(
            action_for(&in_force, "second.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain)
        );
        assert_eq!(
            action_for(&in_force, "third.example.com.", Qtype::of(rt::A)),
            None,
            "half of a failed reload is worse than none of it"
        );
    }

    /// What the caches are owed, and only what they are owed: a QNAME rule
    /// that moved is in force for the next query whatever is held, and a
    /// nameserver rule that moved is not.
    #[test]
    fn only_a_moved_nameserver_rule_reports_a_change() {
        let dir = ScratchDir::new("rpz-reload-versions");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("it loads");

        std::fs::write(&path, feed(2, "second.example.com", None)).expect("rewrite");
        assert!(
            !store.reload().expect("re-reads").delegation_rules_changed,
            "a QNAME rule is consulted before every cache"
        );

        std::fs::write(
            &path,
            feed(3, "second.example.com", Some("ns.evil.example.com")),
        )
        .expect("rewrite");
        assert!(
            store.reload().expect("re-reads").delegation_rules_changed,
            "a nameserver rule is only asked while a delegation is walked"
        );

        // Same file, same serial: an operator who sends SIGHUP hourly must not
        // pay a cold cache for it.
        assert!(
            !store.reload().expect("re-reads").delegation_rules_changed,
            "nothing moved"
        );

        std::fs::write(
            &path,
            feed(4, "second.example.com", Some("ns.other.example.com")),
        )
        .expect("rewrite");
        assert!(store.reload().expect("re-reads").delegation_rules_changed);
    }

    /// #71b: a feed nobody touched is not read again, and the reload hands
    /// back the same indexed zone.
    ///
    /// Pointer identity rather than a timing, because the saving is a parse
    /// that either happened or did not and a count is deterministic where a
    /// wall-clock assertion is a coin toss (`CLAUDE.md` §10). Fails against the
    /// `PolicyZones::load(&self.feeds)` this replaced, which built a new
    /// `PolicyZone` for every feed on every reload.
    #[test]
    fn a_feed_whose_file_did_not_move_is_kept_whole() {
        let dir = ScratchDir::new("rpz-reload-kept");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("it loads");
        let before = store.in_force().zones()[0].clone();

        let reloaded = store.reload().expect("it re-reads");
        assert_eq!(reloaded.reread, 0, "nothing moved, so nothing was parsed");
        assert!(
            Arc::ptr_eq(&before, &reloaded.zones.zones()[0]),
            "an untouched feed must come back as the zone already in force"
        );

        // And the rule is still enforced, which is the thing the saving must
        // not have cost.
        assert_eq!(
            action_for(&store.in_force(), "first.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain)
        );
    }

    /// The other half, and the one that matters: one feed publishing must not
    /// re-read the others, and must still be seen itself.
    #[test]
    fn one_feed_changing_re_reads_only_that_feed() {
        let dir = ScratchDir::new("rpz-reload-one");
        let quiet = dir.write("quiet.zone", &feed(1, "quiet.example.com", None));
        let busy = dir.write("busy.zone", &feed(1, "busy.example.com", None));
        let store = PolicyStore::load(&[
            Feed::new(&quiet, PolicyOverride::Given),
            Feed::new(&busy, PolicyOverride::Given),
        ])
        .expect("both load");
        let before = store.in_force().zones().to_vec();

        std::fs::write(&busy, feed(2, "worse.example.com", None)).expect("rewrite");
        let reloaded = store.reload().expect("it re-reads");
        assert_eq!(reloaded.reread, 1, "one file moved out of two");
        assert!(Arc::ptr_eq(&before[0], &reloaded.zones.zones()[0]));
        assert!(!Arc::ptr_eq(&before[1], &reloaded.zones.zones()[1]));
        assert_eq!(
            action_for(&reloaded.zones, "worse.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain),
            "the feed that did publish has to be in force"
        );
        assert_eq!(
            action_for(&reloaded.zones, "quiet.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain),
            "and the one that did not has to still be"
        );
    }

    /// A digest of a feed says nothing about a file it `$INCLUDE`s, so a feed
    /// with one is read every time (`rdns::zone::FileDigest::of_self_contained`).
    ///
    /// The failure this prevents is the one the re-read exists for: an
    /// operator's edit silently not taken (`CLAUDE.md` §4). `rdnsd`'s reload
    /// path has the same test for the same reason (`TODO.md` #64f).
    #[test]
    fn a_feed_that_includes_another_file_is_always_read_again() {
        let dir = ScratchDir::new("rpz-reload-include");
        dir.write("extra.zone", "included.example.com IN CNAME .\n");
        let path = dir.write(
            "feed.zone",
            &format!(
                "{}$INCLUDE extra.zone\n",
                feed(1, "first.example.com", None)
            ),
        );
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("it loads");
        let before = store.in_force().zones()[0].clone();
        assert_eq!(
            action_for(&store.in_force(), "included.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain),
            "the include was read"
        );

        let reloaded = store.reload().expect("it re-reads");
        assert_eq!(reloaded.reread, 1);
        assert!(
            !Arc::ptr_eq(&before, &reloaded.zones.zones()[0]),
            "the parent file's digest cannot speak for the included one"
        );
    }

    /// What #71f is: a zone this process wrote is installed from the copy it
    /// already holds, and the file is read only to prove it is still that zone.
    ///
    /// Fails against the shape this replaced, where the transfer wrote the file
    /// and the reload parsed all of it back — `reread` would be 1 and the
    /// installed zone a different allocation from the one offered. At a million
    /// rules that parse is 622 ms (`rdns/tests/record_storage.rs`).
    #[test]
    fn a_zone_this_process_wrote_is_installed_without_parsing_it_back() {
        let dir = ScratchDir::new("rpz-offer");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("it loads");

        // What a transfer holds: a zone, and the text it wrote to the file.
        let arrived =
            crate::zone::parse_zone_file(&feed(2, "second.example.com", None), "rpz.invalid.")
                .expect("the transferred zone parses");
        let text = crate::zone_writer::zone_to_string(&arrived).expect("it serializes");
        let written = crate::zone_writer::write_zone_text(&text, &path).expect("it is written");
        store.offer(&written, arrived).expect("the feed is ours");

        let reloaded = store.reload().expect("it re-reads");
        assert_eq!(reloaded.reread, 0, "nothing had to be parsed");
        assert_eq!(reloaded.installed, 1, "one feed came from what was written");
        assert_eq!(
            action_for(&store.in_force(), "second.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain),
            "the rule that arrived is what the next query is decided by"
        );
        assert_eq!(
            action_for(&store.in_force(), "first.example.com.", Qtype::of(rt::A)),
            None,
            "and the rule it replaced is gone"
        );

        // Consumed: a second reload has nothing offered and nothing changed.
        let again = store.reload().expect("it re-reads");
        assert_eq!((again.reread, again.installed), (0, 0));
    }

    /// The property #71f rests on: the zone installed from an offer is the
    /// zone the file parses to, record for record.
    ///
    /// Nothing asserted it before this: `rpz_install.rs`'s "the two shapes must
    /// install the same zone" compares `PolicyZone::records`, which is a
    /// *count*, and five trigger counts beside it — a claim read off a method
    /// name instead of out of the method (`CLAUDE.md` §4). That one is also
    /// `#[ignore]`d, so it guards nothing a suite runs.
    ///
    /// Field by field rather than comparing the two serializations: a
    /// round-trip through the writer would hide anything the writer drops,
    /// which is the half of this worth testing.
    #[test]
    fn what_is_installed_is_what_the_file_would_have_parsed_to() {
        let dir = ScratchDir::new("rpz-offer-equal");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("it loads");

        let arrived = crate::zone::parse_zone_file(
            &feed(2, "second.example.com", Some("ns.bad.example")),
            "rpz.invalid.",
        )
        .expect("the transferred zone parses");
        let text = crate::zone_writer::zone_to_string(&arrived).expect("it serializes");
        let written = crate::zone_writer::write_zone_text(&text, &path).expect("it is written");
        store.offer(&written, arrived).expect("the feed is ours");
        let reloaded = store.reload().expect("it installs");
        assert_eq!(
            reloaded.installed, 1,
            "the offer has to be what was installed, or this compares a parse with itself"
        );

        let parsed = PolicyZone::load(&path, PolicyOverride::Given).expect("the file parses");
        let in_force = store.in_force();
        let installed = in_force.zones()[0].zone();
        let from_file = parsed.zone();
        assert_eq!(installed.records().len(), from_file.records().len());
        for (theirs, ours) in from_file.records().iter().zip(installed.records()) {
            assert_eq!(theirs.name, ours.name);
            assert_eq!(theirs.ttl, ours.ttl);
            assert_eq!(theirs.class, ours.class);
            assert_eq!(theirs.rdata, ours.rdata);
        }
        assert_eq!(installed.origin(), from_file.origin());
        assert_eq!(
            in_force.zones()[0].trigger_counts(),
            parsed.trigger_counts(),
            "and the triggers derived from them"
        );
    }

    /// The digest is the whole test, so a file somebody else rewrote between
    /// the write and the reload is parsed rather than papered over with the
    /// zone this process meant to be there.
    ///
    /// The failure it prevents is an edit silently not taken (`CLAUDE.md` §4) —
    /// the same one `of_self_contained` exists for, arriving from the other
    /// direction.
    #[test]
    fn an_offer_is_declined_when_the_file_no_longer_holds_it() {
        let dir = ScratchDir::new("rpz-offer-stale");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("it loads");

        let arrived =
            crate::zone::parse_zone_file(&feed(2, "second.example.com", None), "rpz.invalid.")
                .expect("the transferred zone parses");
        let text = crate::zone_writer::zone_to_string(&arrived).expect("it serializes");
        let written = crate::zone_writer::write_zone_text(&text, &path).expect("it is written");
        store.offer(&written, arrived).expect("the feed is ours");

        // Somebody else — a cron job, an operator — writes the file after the
        // transfer did.
        std::fs::write(&path, feed(3, "third.example.com", None)).expect("rewrite");

        let reloaded = store.reload().expect("it re-reads");
        assert_eq!(
            reloaded.installed, 0,
            "the offer no longer matches the file"
        );
        assert_eq!(reloaded.reread, 1, "so the file was parsed");
        assert_eq!(
            action_for(&store.in_force(), "third.example.com.", Qtype::of(rt::A)),
            Some(Action::Nxdomain),
            "what is in force is what the file says"
        );
        assert_eq!(
            action_for(&store.in_force(), "second.example.com.", Qtype::of(rt::A)),
            None
        );
    }

    /// A path no feed reads is refused rather than dropped: the zone would
    /// never be in force, and the caller is the one that can say so.
    #[test]
    fn a_zone_written_where_no_feed_reads_is_refused() {
        let dir = ScratchDir::new("rpz-offer-unknown");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("it loads");

        let stray =
            crate::zone::parse_zone_file(&feed(2, "second.example.com", None), "rpz.invalid.")
                .expect("it parses");
        let text = crate::zone_writer::zone_to_string(&stray).expect("it serializes");
        let elsewhere = dir.join("other.zone");
        let written =
            crate::zone_writer::write_zone_text(&text, &elsewhere).expect("it is written");
        let refused = store
            .offer(&written, stray)
            .expect_err("no feed reads that path");
        assert!(
            refused.to_string().contains("other.zone"),
            "the message names the path: {refused}"
        );
    }

    /// A store nothing was loaded from reloads nothing: the `--rpz`-less
    /// resolver must not have SIGHUP say "policy zones re-read".
    #[test]
    fn a_store_with_no_files_is_not_configured() {
        let store = PolicyStore::in_memory(PolicyZones::default());
        assert!(!store.is_configured());
        assert!(store.in_force().is_empty());
    }
}
