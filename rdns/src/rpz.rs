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
use crate::security::prefix_matches;
use crate::zone::{parse_zone_file_at, Located, NameKind, Zone, ZoneRecord};
use crate::{Name, NameRef, ParsedRecord, Qtype, ResourceRecord, Serial};
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

/// The label that ends the owner name of every trigger type that is not a
/// QNAME.
///
/// A query name whose own last label is one of these would otherwise build a
/// trigger name inside one of those subtrees and match an address rule by
/// accident.
const SPECIAL_LABELS: [&[u8]; 4] = [b"rpz-client-ip", b"rpz-ip", b"rpz-nsdname", b"rpz-nsip"];

/// One address rule: the prefix it covers, and the owner name whose RRset is
/// the action.
#[derive(Debug, Clone)]
struct IpTrigger {
    addr: IpAddr,
    prefix: u8,
    owner: Name,
}

/// One policy zone, indexed for the three questions a query asks of it.
#[derive(Debug)]
pub struct PolicyZone {
    zone: Zone,
    policy: PolicyOverride,
    /// Longest prefix first, so the first match is the most specific one.
    client_ip: Vec<IpTrigger>,
    response_ip: Vec<IpTrigger>,
    ns_ip: Vec<IpTrigger>,
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
        let fallback = crate::zone::origin_from_path(&path.to_string_lossy());
        let zone = parse_zone_file_at(path, &fallback)
            .map_err(|e| ConfigError::new(format!("RPZ {}: {e}", path.display())))?;
        PolicyZone::new(zone, policy)
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
        let mut seen: Vec<Name> = Vec::new();
        for record in zone.records() {
            let owner = record.name.as_ref();
            let Some(kind) = trigger_subtree(owner, origin) else {
                continue;
            };
            // One rule per owner name, however many records sit at it.
            if seen.iter().any(|s| s.as_ref() == owner) {
                continue;
            }
            seen.push(record.name.clone());
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
                owner: record.name.clone(),
            };
            match kind {
                b"rpz-client-ip" => client_ip.push(trigger),
                b"rpz-nsip" => ns_ip.push(trigger),
                _ => response_ip.push(trigger),
            }
        }
        // Longest prefix wins, which a linear scan gives once the list is in
        // that order. These lists are tens of entries: a feed's bulk is QNAME
        // triggers, and those the zone's own index answers.
        client_ip.sort_by_key(|rule| std::cmp::Reverse(rule.prefix));
        response_ip.sort_by_key(|rule| std::cmp::Reverse(rule.prefix));
        ns_ip.sort_by_key(|rule| std::cmp::Reverse(rule.prefix));

        let nsdname_root = Name::prefixed(b"rpz-nsdname", origin).map_err(|e| {
            ConfigError::new(format!(
                "the policy zone {} is too long to hold NSDNAME triggers: {e}",
                origin.to_presentation()
            ))
        })?;

        Ok(PolicyZone {
            zone,
            policy,
            client_ip,
            response_ip,
            ns_ip,
            nsdname_root,
            nsdname,
        })
    }

    pub fn origin(&self) -> NameRef<'_> {
        self.zone.origin()
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
        rules: &[IpTrigger],
        addr: IpAddr,
        qname: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<Action> {
        let rule = rules.iter().find(|rule| rule.matches(addr))?;
        self.action_at(rule.owner.as_ref(), qname, qtype)
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
fn rewritten(record: &ZoneRecord, qname: NameRef<'_>) -> ResourceRecord {
    ResourceRecord {
        name: qname.to_owned(),
        class: record.class,
        ttl: record.ttl,
        rdata: record.rdata.clone(),
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

impl IpTrigger {
    fn matches(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(rule), IpAddr::V4(peer)) => {
                prefix_matches(&rule.octets(), &peer.octets(), self.prefix)
            }
            (IpAddr::V6(rule), IpAddr::V6(peer)) => {
                prefix_matches(&rule.octets(), &peer.octets(), self.prefix)
            }
            // Families do not mix, as in `security::TransferAcl`: a v4 rule
            // must not match a v4-mapped v6 address.
            _ => false,
        }
    }
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
#[derive(Debug, Default)]
pub struct PolicyZones {
    zones: Vec<PolicyZone>,
}

impl PolicyZones {
    /// Load each file, in the order they will be consulted.
    ///
    /// All-or-nothing: a feed that does not parse must not leave the resolver
    /// enforcing a policy shorter than the one configured (`CLAUDE.md` §4).
    pub fn load(paths: &[PathBuf], policy: PolicyOverride) -> ConfigResult<PolicyZones> {
        let mut zones = Vec::with_capacity(paths.len());
        for path in paths {
            zones.push(PolicyZone::load(path, policy)?);
        }
        Ok(PolicyZones { zones })
    }

    /// Zones already built, in the order they are consulted — for a caller
    /// that did not read them from files.
    pub fn from_zones(zones: Vec<PolicyZone>) -> PolicyZones {
        PolicyZones { zones }
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    pub fn zones(&self) -> &[PolicyZone] {
        &self.zones
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
        self.zones.iter().any(PolicyZone::watches_delegations)
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
    paths: Vec<PathBuf>,
    policy: PolicyOverride,
    current: RwLock<Arc<PolicyZones>>,
}

impl PolicyStore {
    /// Read every file, or fail without installing any of them.
    pub fn load(paths: &[PathBuf], policy: PolicyOverride) -> ConfigResult<Arc<PolicyStore>> {
        let zones = PolicyZones::load(paths, policy)?;
        Ok(Arc::new(PolicyStore {
            paths: paths.to_vec(),
            policy,
            current: RwLock::new(Arc::new(zones)),
        }))
    }

    /// A store over zones that came from somewhere other than a file, for a
    /// caller that has already built them. Reloading one re-reads nothing.
    pub fn in_memory(zones: PolicyZones) -> Arc<PolicyStore> {
        Arc::new(PolicyStore {
            paths: Vec::new(),
            policy: PolicyOverride::Given,
            current: RwLock::new(Arc::new(zones)),
        })
    }

    /// Whether any file was named, and so whether a reload has anything to do.
    pub fn is_configured(&self) -> bool {
        !self.paths.is_empty()
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
        let zones = Arc::new(PolicyZones::load(&self.paths, self.policy)?);
        let mut guard = match self.current.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let delegation_rules_changed = zones.delegation_versions() != guard.delegation_versions();
        *guard = zones.clone();
        Ok(Reloaded {
            zones,
            delegation_rules_changed,
        })
    }
}

/// What a reload installed, and the one thing a caller holding a cache has to
/// know about it.
#[derive(Debug)]
pub struct Reloaded {
    /// The set now in force.
    pub zones: Arc<PolicyZones>,
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

    fn policy_zones(policy: PolicyOverride) -> PolicyZones {
        let zone = parse_zone_file(POLICY, ORIGIN).expect("the policy zone parses");
        PolicyZones {
            zones: vec![PolicyZone::new(zone, policy).expect("it indexes")],
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
                PolicyZone::new(local, PolicyOverride::Given).unwrap(),
                PolicyZone::new(feed, PolicyOverride::Given).unwrap(),
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
        let store = PolicyStore::load(std::slice::from_ref(&path), PolicyOverride::Given)
            .expect("it loads");
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

    /// All-or-nothing, as at startup: one unparseable file out of two must not
    /// leave the resolver enforcing half the policy (`CLAUDE.md` §4).
    #[test]
    fn a_feed_that_will_not_parse_leaves_the_previous_ones_in_force() {
        let dir = ScratchDir::new("rpz-reload-broken");
        let first = dir.write("first.zone", &feed(1, "first.example.com", None));
        let second = dir.write("second.zone", &feed(1, "second.example.com", None));
        let store = PolicyStore::load(&[first.clone(), second.clone()], PolicyOverride::Given)
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
        let store = PolicyStore::load(std::slice::from_ref(&path), PolicyOverride::Given)
            .expect("it loads");

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

    /// A store nothing was loaded from reloads nothing: the `--rpz`-less
    /// resolver must not have SIGHUP say "policy zones re-read".
    #[test]
    fn a_store_with_no_files_is_not_configured() {
        let store = PolicyStore::in_memory(PolicyZones::default());
        assert!(!store.is_configured());
        assert!(store.in_force().is_empty());
    }
}
