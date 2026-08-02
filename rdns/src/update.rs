//! Dynamic update (RFC 2136): reading an UPDATE, and deciding what it asks for.
//!
//! **What this module does and does not do.** It turns an UPDATE message into a
//! checked list of prerequisites and changes, evaluates the prerequisites
//! against a zone, and stops. It never mutates a zone, touches a file, bumps a
//! serial or looks at a TSIG key. That seam is deliberate: `TODO.md` #10 lists
//! six things dynamic UPDATE drags in — the prerequisite language, per-zone
//! authorization, serial handling that collides with re-signing (#8),
//! incremental re-signing, writing the zone back out, and the journal (#7 step
//! 6) — and says they must not be designed separately. The four *policy* ones
//! all live on the far side of "here is what this message would change", which
//! is exactly where this module ends. What it produces is also the shape a
//! journal entry and an IXFR delta both want.
//!
//! **The sections are the ordinary four, renamed** (RFC 2136 §2.2). The question
//! section is the Zone section, the answer section is the Prerequisite section,
//! the authority section is the Update section, and the additional section stays
//! itself — which is where a TSIG goes. So no new wire parsing is needed and
//! none is done here: [`DnsMessage`] already carries all of it.
//!
//! **Class is the verb.** This is the part of RFC 2136 that surprises people and
//! the reason the parsing below is a table rather than a few `if`s: an update
//! record's CLASS says what to *do* with it, not what kind of data it is. The
//! zone's own class means add, `ANY` (255) means delete a whole RRset or name,
//! and `NONE` (254) means delete one specific record. `QueryClass::None` being a
//! real value with a real meaning here — rather than a sentinel — is why
//! `CLAUDE.md` §2 insisted the parse keep it.

use crate::utils::{is_at_or_under, record_types as rt};
use crate::zone::Zone;
use crate::Qtype;
use crate::Rtype;
use crate::Ttl;
use crate::{DnsMessage, OpCode, QueryClass, RecordData, ResourceRecord, ResponseCode};

/// Why an UPDATE was refused, and the RCODE that says so on the wire.
///
/// One type rather than a variant per RFC section, because every caller does the
/// same two things with it: put `rcode` in the reply, and log `why`. The
/// category *is* the rcode — RFC 2136 §3 assigns a specific one to each way an
/// update can be rejected — and the string is the detail no rcode can carry
/// (`CLAUDE.md` §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub rcode: ResponseCode,
    pub why: String,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:?})", self.why, self.rcode)
    }
}

impl std::error::Error for Rejected {}

impl Rejected {
    fn new(rcode: ResponseCode, why: impl Into<String>) -> Self {
        Rejected {
            rcode,
            why: why.into(),
        }
    }
}

/// A condition the zone must satisfy before any change is applied (RFC 2136
/// §2.4). Five forms, and the encoding of each is a combination of CLASS, TYPE
/// and whether there is any RDATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerequisite {
    /// §2.4.1 — some RRset of this type exists at this name, whatever it holds.
    /// CLASS=ANY, RDLENGTH=0.
    RrsetExists { name: String, rtype: Rtype },
    /// §2.4.2 — an RRset of this type exists at this name *and* holds exactly
    /// these records. CLASS is the zone's, and there is RDATA.
    ///
    /// "Exactly" is the part worth stating: §3.2.3 compares the whole RRset for
    /// equality as a set, so a prerequisite naming two of three records fails.
    RrsetExistsWithValue {
        name: String,
        rtype: Rtype,
        rdatas: Vec<RecordData>,
    },
    /// §2.4.3 — no RRset of this type exists at this name. CLASS=NONE.
    RrsetDoesNotExist { name: String, rtype: Rtype },
    /// §2.4.4 — at least one RR exists at this name. CLASS=ANY, TYPE=ANY.
    NameInUse { name: String },
    /// §2.4.5 — no RR exists at this name. CLASS=NONE, TYPE=ANY.
    NameNotInUse { name: String },
}

/// One thing an UPDATE asks to change (RFC 2136 §2.5). Four forms, again keyed
/// on CLASS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// §2.5.1 — add this record to its RRset, or create the RRset. CLASS is the
    /// zone's. The only form that carries a TTL that matters.
    Add(ResourceRecord),
    /// §2.5.2 — delete every record of this type at this name. CLASS=ANY.
    DeleteRrset { name: String, rtype: Rtype },
    /// §2.5.3 — delete every RRset at this name. CLASS=ANY, TYPE=ANY.
    DeleteName { name: String },
    /// §2.5.4 — delete the one record that matches this name, type and RDATA.
    /// CLASS=NONE. The TTL is ignored in the comparison (§2.5.4), which is why
    /// this carries rdata rather than a whole record.
    DeleteRecord {
        name: String,
        rtype: Rtype,
        rdata: RecordData,
    },
}

/// An UPDATE that has been read and found well-formed: which zone, what must
/// already be true, and what would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    /// The zone this update is for, from the Zone section (§2.3).
    pub zone: String,
    pub prerequisites: Vec<Prerequisite>,
    pub changes: Vec<Change>,
}

/// Read an UPDATE message into an [`UpdateRequest`], or reject it.
///
/// This is RFC 2136 §3.1 (the zone section), the form rules of §2.4 and §2.5,
/// and §3.4.1's prescan — everything that can be decided from the message alone.
/// Whether the *server* holds the named zone is the caller's question, because
/// only the caller knows which zones it serves; §3.1's NOTZONE is raised here
/// only for a record that falls outside the zone the message itself names.
pub fn parse(msg: &DnsMessage) -> Result<UpdateRequest, Rejected> {
    if msg.opcode != OpCode::Update {
        return Err(Rejected::new(
            ResponseCode::FormatError,
            format!("opcode {:?} is not UPDATE", msg.opcode),
        ));
    }

    // §3.1: exactly one zone, of type SOA. "If the zone section contains more
    // than one RR, or an RR whose ZTYPE is not SOA, the server shall return
    // FORMERR."
    let [zone_section] = msg.queries.as_slice() else {
        return Err(Rejected::new(
            ResponseCode::FormatError,
            format!(
                "an UPDATE names exactly one zone, this one names {}",
                msg.queries.len()
            ),
        ));
    };
    if !zone_section.qtype.is(rt::SOA) {
        return Err(Rejected::new(
            ResponseCode::FormatError,
            format!(
                "the zone section's type is {} and RFC 2136 §3.1 requires SOA",
                zone_section.qtype
            ),
        ));
    }
    let zone = zone_section.qname.clone();
    let zone_class = zone_section.qclass;

    let prerequisites = msg
        .answers
        .iter()
        .map(|rr| read_prerequisite(rr, &zone, zone_class))
        .collect::<Result<Vec<_>, _>>()?;
    let changes = msg
        .authorities
        .iter()
        .map(|rr| read_change(rr, &zone, zone_class))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(UpdateRequest {
        zone,
        prerequisites,
        changes,
    })
}

/// One record of the Prerequisite section (RFC 2136 §2.4, checked per §3.2).
fn read_prerequisite(
    rr: &ResourceRecord,
    zone: &str,
    zone_class: QueryClass,
) -> Result<Prerequisite, Rejected> {
    // §3.2: "For RRs in this section whose CLASS is not ANY [...] TTL must be
    // zero", and §2.4 gives TTL=0 for every form including the value-dependent
    // one. A non-zero TTL is FORMERR rather than something to round off: it
    // means the sender built the section from a template it did not read.
    if rr.ttl != Ttl::ZERO {
        return Err(Rejected::new(
            ResponseCode::FormatError,
            format!(
                "prerequisite for {} has TTL {} and RFC 2136 §2.4 requires 0",
                rr.name, rr.ttl
            ),
        ));
    }
    in_zone_or_notzone(&rr.name, zone, "prerequisite")?;

    let rtype = rr.rdata.rtype();
    let empty = rr.rdata.bytes().is_empty();
    match QueryClass::from(rr.class) {
        // §2.4.4 / §2.4.1 — ANY: "is anything there?", either at the name or
        // for one type at it.
        QueryClass::Any if rtype == rt::ANY && empty => Ok(Prerequisite::NameInUse {
            name: rr.name.clone(),
        }),
        QueryClass::Any if empty => Ok(Prerequisite::RrsetExists {
            name: rr.name.clone(),
            rtype,
        }),
        // §2.4.5 / §2.4.3 — NONE: the same two questions, negated.
        QueryClass::None if rtype == rt::ANY && empty => Ok(Prerequisite::NameNotInUse {
            name: rr.name.clone(),
        }),
        QueryClass::None if empty => Ok(Prerequisite::RrsetDoesNotExist {
            name: rr.name.clone(),
            rtype,
        }),
        // §2.4.2 — the zone's own class, with RDATA: the RRset must hold
        // exactly this. Collected per name and type by the caller below.
        class if class == zone_class && !empty => Ok(Prerequisite::RrsetExistsWithValue {
            name: rr.name.clone(),
            rtype,
            rdatas: vec![rr.rdata.clone()],
        }),
        _ => Err(Rejected::new(
            ResponseCode::FormatError,
            format!(
                "prerequisite for {} has class {} with {} of RDATA, which is none \
                 of the five forms in RFC 2136 §2.4",
                rr.name,
                rr.class,
                if empty { "none" } else { "some" }
            ),
        )),
    }
}

/// One record of the Update section (RFC 2136 §2.5, prescanned per §3.4.1).
fn read_change(
    rr: &ResourceRecord,
    zone: &str,
    zone_class: QueryClass,
) -> Result<Change, Rejected> {
    // §3.4.1: "If any RR's NAME is not within the zone specified in the Zone
    // Section, signal NOTZONE to the requestor." An update that reaches outside
    // its own zone is the shape that would let one zone's key write another
    // zone's data.
    in_zone_or_notzone(&rr.name, zone, "update")?;

    let rtype = rr.rdata.rtype();
    let empty = rr.rdata.bytes().is_empty();
    // §3.4.1 again: a meta-type may never be added, and only ANY may be
    // deleted. "ANY" as something to *add* is not data, it is a question.
    let deleting = matches!(
        QueryClass::from(rr.class),
        QueryClass::Any | QueryClass::None
    );
    if !deleting && (rtype == rt::ANY || rtype == rt::AXFR || rtype == rt::IXFR) {
        return Err(Rejected::new(
            ResponseCode::FormatError,
            format!(
                "an UPDATE may not add type {rtype} at {}: RFC 2136 §3.4.1 \
                 forbids a meta-type here",
                rr.name
            ),
        ));
    }

    match QueryClass::from(rr.class) {
        // §2.5.3 / §2.5.2 — ANY: delete everything at the name, or one RRset.
        // Both require an empty RDATA and a zero TTL.
        QueryClass::Any if rtype == rt::ANY && empty && rr.ttl == Ttl::ZERO => {
            Ok(Change::DeleteName {
                name: rr.name.clone(),
            })
        }
        QueryClass::Any if empty && rr.ttl == Ttl::ZERO => Ok(Change::DeleteRrset {
            name: rr.name.clone(),
            rtype,
        }),
        // §2.5.4 — NONE with RDATA: delete exactly this record. The TTL is
        // "ignored" by the RFC, which means it must be zero on the wire and is
        // not part of the comparison.
        QueryClass::None if !empty && rr.ttl == Ttl::ZERO => Ok(Change::DeleteRecord {
            name: rr.name.clone(),
            rtype,
            rdata: rr.rdata.clone(),
        }),
        // §2.5.1 — the zone's class: add it. The one form with a meaningful TTL.
        class if class == zone_class && !empty => Ok(Change::Add(rr.clone())),
        _ => Err(Rejected::new(
            ResponseCode::FormatError,
            format!(
                "update record for {} has class {}, TTL {} and {} of RDATA, which \
                 is none of the four forms in RFC 2136 §2.5",
                rr.name,
                rr.class,
                rr.ttl,
                if empty { "none" } else { "some" }
            ),
        )),
    }
}

/// RFC 2136 §3.1 and §3.4.1: a name outside the zone the message names is
/// NOTZONE, not a refusal and not a format error.
fn in_zone_or_notzone(name: &str, zone: &str, what: &str) -> Result<(), Rejected> {
    if is_at_or_under(name, zone) {
        Ok(())
    } else {
        Err(Rejected::new(
            ResponseCode::NameNotInZone,
            format!("{what} record for {name} is outside {zone}"),
        ))
    }
}

/// Check every prerequisite against the zone (RFC 2136 §3.2).
///
/// `Ok(())` when they all hold. The RCODE on failure is the specific one §3.2
/// assigns to that form of prerequisite, and the four are not
/// interchangeable — a client uses them to tell "the name is not there" from
/// "the name is there but this type is not", which is the whole point of having
/// four codes rather than one.
///
/// **Prerequisites are checked as a set, before any change is applied**, which
/// is what makes an UPDATE a transaction: §3.2's checks all happen first, and
/// §3.4 only runs if every one of them passed.
pub fn check_prerequisites(zone: &Zone, prerequisites: &[Prerequisite]) -> Result<(), Rejected> {
    // §2.4.2's records are per-RR on the wire but per-RRset in meaning: several
    // records with the same name and type are one prerequisite naming a whole
    // RRset. Gathering them first is what makes the "exactly this set"
    // comparison below possible at all.
    let mut value_sets: Vec<(String, Rtype, Vec<RecordData>)> = Vec::new();

    for prerequisite in prerequisites {
        match prerequisite {
            Prerequisite::RrsetExists { name, rtype } => {
                if zone.query(name, Qtype::of(*rtype)).is_empty() {
                    return Err(Rejected::new(
                        ResponseCode::NoSuchResourceRecordSet,
                        format!("{name} has no {rtype} RRset"),
                    ));
                }
            }
            Prerequisite::RrsetDoesNotExist { name, rtype } => {
                if !zone.query(name, Qtype::of(*rtype)).is_empty() {
                    return Err(Rejected::new(
                        ResponseCode::ResourceRecordSetExistsForSomeReason,
                        format!("{name} already has a {rtype} RRset"),
                    ));
                }
            }
            // §2.4.4: "at least one RR with a specified NAME [...] must exist".
            // `holds_name` is the literal question — records *at* this name —
            // rather than `name_exists`, which is true for a name a wildcard
            // reaches and for an empty non-terminal. An update must not be
            // allowed to believe a name is there because something could
            // synthesize it.
            Prerequisite::NameInUse { name } => {
                if !zone.holds_name(name) {
                    return Err(Rejected::new(
                        ResponseCode::NoSuchDomain,
                        format!("{name} is not in use"),
                    ));
                }
            }
            Prerequisite::NameNotInUse { name } => {
                if zone.holds_name(name) {
                    return Err(Rejected::new(
                        ResponseCode::DomainExistsForSomeReason,
                        format!("{name} is already in use"),
                    ));
                }
            }
            Prerequisite::RrsetExistsWithValue {
                name,
                rtype,
                rdatas,
            } => {
                match value_sets
                    .iter_mut()
                    .find(|(n, t, _)| n == name && t == rtype)
                {
                    Some((_, _, collected)) => collected.extend(rdatas.iter().cloned()),
                    None => value_sets.push((name.clone(), *rtype, rdatas.clone())),
                }
            }
        }
    }

    for (name, rtype, wanted) in value_sets {
        let held: Vec<RecordData> = zone
            .query(&name, Qtype::of(rtype))
            .into_iter()
            .map(|r| r.rdata.clone())
            .collect();
        if held.is_empty() {
            return Err(Rejected::new(
                ResponseCode::NoSuchResourceRecordSet,
                format!("{name} has no {rtype} RRset to match against"),
            ));
        }
        // §3.2.3: the RRsets must be equal *as sets* — same members, order
        // irrelevant, and neither may hold anything the other does not.
        if !same_set(&held, &wanted) {
            return Err(Rejected::new(
                ResponseCode::NoSuchResourceRecordSet,
                format!(
                    "{name}'s {rtype} RRset holds {} records and the prerequisite \
                     names {}, and RFC 2136 §3.2.3 compares them as whole sets",
                    held.len(),
                    wanted.len()
                ),
            ));
        }
    }

    Ok(())
}

/// Set equality over RDATA, with no ordering assumption and no sort.
///
/// `RecordData` is not `Ord`, so this is the quadratic comparison — which is the
/// right one here: an RRset is a handful of records, and a prerequisite naming
/// enough of them for that to matter would not fit a datagram.
fn same_set(held: &[RecordData], wanted: &[RecordData]) -> bool {
    held.len() == wanted.len()
        && held.iter().all(|h| wanted.contains(h))
        && wanted.iter().all(|w| held.contains(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::parse_zone_file;
    use crate::Class;
    use crate::{ParsedRecord, QuerySection};
    use std::net::Ipv4Addr;

    const ZONE: &str = "$ORIGIN example.com.
$TTL 3600
@    IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@    IN NS  ns1.example.com.
ns1  IN A   192.0.2.1
www  IN A   192.0.2.10
www  IN A   192.0.2.11
mail IN MX  10 mx.example.com.
";

    fn zone() -> Zone {
        parse_zone_file(ZONE, "example.com.").expect("the test zone parses")
    }

    fn a(addr: &str) -> RecordData {
        RecordData::from_parsed(&ParsedRecord::A(addr.parse::<Ipv4Addr>().unwrap()))
            .expect("an A record encodes")
    }

    /// An UPDATE message: zone section, then the prerequisite and update
    /// sections in the answer and authority slots (RFC 2136 §2.2).
    fn update(prerequisites: Vec<ResourceRecord>, changes: Vec<ResourceRecord>) -> DnsMessage {
        DnsMessage {
            id: 0x2136,
            response: false,
            opcode: OpCode::Update,
            authoritive: false,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: "example.com.".to_string(),
                qtype: Qtype::of(rt::SOA),
                qclass: QueryClass::IN,
            }],
            answers: prerequisites,
            authorities: changes,
            additionals: Vec::new(),
            edns: None,
        }
    }

    fn rr(name: &str, class: Class, ttl: Ttl, rdata: RecordData) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            class,
            ttl,
            rdata,
        }
    }

    /// An empty RDATA of a given type: how §2.4 and §2.5 spell "this type, no
    /// value".
    fn bare(rtype: Rtype) -> RecordData {
        RecordData::new(rtype, Vec::new()).expect("a type with no value is storable")
    }

    /// All five prerequisite forms of RFC 2136 §2.4, each identified by the
    /// CLASS/TYPE/RDLENGTH combination the RFC gives it.
    ///
    /// Written as a table because that is what §2.4 is: the same record
    /// structure means five different questions depending on three fields, and
    /// an `if` chain over them is where a reader loses track of which is which.
    #[test]
    fn the_five_prerequisite_forms_are_read_as_rfc_2136_defines_them() {
        let cases = vec![
            (
                rr(
                    "www.example.com.",
                    Class::new(255),
                    Ttl::from_secs(0),
                    bare(rt::A),
                ),
                Prerequisite::RrsetExists {
                    name: "www.example.com.".to_string(),
                    rtype: rt::A,
                },
                "§2.4.1 CLASS=ANY, an RRset of this type exists",
            ),
            (
                rr(
                    "www.example.com.",
                    Class::new(1),
                    Ttl::from_secs(0),
                    a("192.0.2.10"),
                ),
                Prerequisite::RrsetExistsWithValue {
                    name: "www.example.com.".to_string(),
                    rtype: rt::A,
                    rdatas: vec![a("192.0.2.10")],
                },
                "§2.4.2 CLASS=zone, and it holds exactly this",
            ),
            (
                rr(
                    "nope.example.com.",
                    Class::new(254),
                    Ttl::from_secs(0),
                    bare(rt::A),
                ),
                Prerequisite::RrsetDoesNotExist {
                    name: "nope.example.com.".to_string(),
                    rtype: rt::A,
                },
                "§2.4.3 CLASS=NONE, no such RRset",
            ),
            (
                rr(
                    "www.example.com.",
                    Class::new(255),
                    Ttl::from_secs(0),
                    bare(rt::ANY),
                ),
                Prerequisite::NameInUse {
                    name: "www.example.com.".to_string(),
                },
                "§2.4.4 CLASS=ANY TYPE=ANY, the name is in use",
            ),
            (
                rr(
                    "nope.example.com.",
                    Class::new(254),
                    Ttl::from_secs(0),
                    bare(rt::ANY),
                ),
                Prerequisite::NameNotInUse {
                    name: "nope.example.com.".to_string(),
                },
                "§2.4.5 CLASS=NONE TYPE=ANY, the name is not in use",
            ),
        ];

        for (record, expected, what) in cases {
            let parsed = parse(&update(vec![record], Vec::new())).expect(what);
            assert_eq!(parsed.prerequisites, vec![expected], "{what}");
        }
    }

    /// And all four update forms of §2.5, which are keyed on CLASS in the same
    /// way — the field that says what kind of data a record is, being used to
    /// say what to do with it.
    #[test]
    fn the_four_update_forms_are_read_as_rfc_2136_defines_them() {
        let cases = vec![
            (
                rr(
                    "new.example.com.",
                    Class::new(1),
                    Ttl::from_secs(3600),
                    a("192.0.2.50"),
                ),
                Change::Add(rr(
                    "new.example.com.",
                    Class::new(1),
                    Ttl::from_secs(3600),
                    a("192.0.2.50"),
                )),
                "§2.5.1 CLASS=zone, add it",
            ),
            (
                rr(
                    "www.example.com.",
                    Class::new(255),
                    Ttl::from_secs(0),
                    bare(rt::A),
                ),
                Change::DeleteRrset {
                    name: "www.example.com.".to_string(),
                    rtype: rt::A,
                },
                "§2.5.2 CLASS=ANY, delete the RRset",
            ),
            (
                rr(
                    "www.example.com.",
                    Class::new(255),
                    Ttl::from_secs(0),
                    bare(rt::ANY),
                ),
                Change::DeleteName {
                    name: "www.example.com.".to_string(),
                },
                "§2.5.3 CLASS=ANY TYPE=ANY, delete every RRset at the name",
            ),
            (
                rr(
                    "www.example.com.",
                    Class::new(254),
                    Ttl::from_secs(0),
                    a("192.0.2.11"),
                ),
                Change::DeleteRecord {
                    name: "www.example.com.".to_string(),
                    rtype: rt::A,
                    rdata: a("192.0.2.11"),
                },
                "§2.5.4 CLASS=NONE with RDATA, delete exactly this record",
            ),
        ];

        for (record, expected, what) in cases {
            let parsed = parse(&update(Vec::new(), vec![record])).expect(what);
            assert_eq!(parsed.changes, vec![expected], "{what}");
        }
    }

    /// §3.1: one zone, and it is an SOA. Both halves, because a message naming
    /// two zones is a message whose changes cannot all be applied atomically
    /// and whose second zone would otherwise be silently ignored.
    #[test]
    fn the_zone_section_names_exactly_one_zone_of_type_soa() {
        let mut two = update(Vec::new(), Vec::new());
        two.queries.push(QuerySection {
            qname: "other.test.".to_string(),
            qtype: Qtype::of(rt::SOA),
            qclass: QueryClass::IN,
        });
        assert_eq!(
            parse(&two).unwrap_err().rcode,
            ResponseCode::FormatError,
            "two zones in one UPDATE"
        );

        let mut not_soa = update(Vec::new(), Vec::new());
        not_soa.queries[0].qtype = Qtype::of(rt::A);
        assert_eq!(
            parse(&not_soa).unwrap_err().rcode,
            ResponseCode::FormatError,
            "the zone section's type must be SOA"
        );

        let mut none = update(Vec::new(), Vec::new());
        none.queries.clear();
        assert_eq!(parse(&none).unwrap_err().rcode, ResponseCode::FormatError);
    }

    /// §3.4.1: a record outside the zone the message names is NOTZONE — its own
    /// code, distinct from REFUSED.
    ///
    /// This is the check that stops one zone's update writing another zone's
    /// data, which is the same shape as the transfer authorization bug
    /// `CLAUDE.md` §16 records: a request that names something it was not
    /// scoped to.
    #[test]
    fn a_record_outside_the_named_zone_is_notzone() {
        let outside = rr(
            "www.elsewhere.test.",
            Class::new(1),
            Ttl::from_secs(3600),
            a("192.0.2.50"),
        );
        assert_eq!(
            parse(&update(Vec::new(), vec![outside.clone()]))
                .unwrap_err()
                .rcode,
            ResponseCode::NameNotInZone,
            "an update record outside the zone"
        );

        let outside_prereq = rr(
            "www.elsewhere.test.",
            Class::new(255),
            Ttl::from_secs(0),
            bare(rt::A),
        );
        assert_eq!(
            parse(&update(vec![outside_prereq], Vec::new()))
                .unwrap_err()
                .rcode,
            ResponseCode::NameNotInZone,
            "a prerequisite outside the zone"
        );

        // `notexample.com.` ends with the zone's name and is a different zone:
        // the boundary has to land on a label separator (`CLAUDE.md` §7's
        // shared `is_at_or_under`).
        let lookalike = rr(
            "notexample.com.",
            Class::new(1),
            Ttl::from_secs(3600),
            a("192.0.2.50"),
        );
        assert_eq!(
            parse(&update(Vec::new(), vec![lookalike]))
                .unwrap_err()
                .rcode,
            ResponseCode::NameNotInZone,
            "a name that merely ends with the zone's name"
        );
    }

    /// **The whole of §2.4 and §2.5, over an actual wire.**
    ///
    /// Every other test in this module hands [`parse`] a `DnsMessage` built in
    /// memory, which is `CLAUDE.md` §1's failure mode written out: the message
    /// never crossed the boundary a real one crosses, so the reading half was
    /// checked against nothing but itself.
    ///
    /// It was hiding a defect that made this whole module unreachable. §2.4.1,
    /// §2.4.3, §2.4.4, §2.4.5, §2.5.2 and §2.5.3 all spell their record with
    /// **RDLENGTH=0** — it names a type and carries no value — and
    /// `ParsedRecord::decode` rejected that for every type it had a decoder for,
    /// because an A with no bytes is four bytes short. `RecordData::from_wire`
    /// runs per record as the message is read, so the whole UPDATE was FORMERR
    /// before a line of this file ran: every value-independent prerequisite and
    /// every RRset deletion was unreadable.
    ///
    /// **Watched failing against the old decoder**, which is what makes this a
    /// regression test rather than a restatement (§1): `try_from_bytes` returned
    /// `Malformed { what: "RDATA", detail: "a fixed-width field has the wrong
    /// length" }`, and the `expect` below fired.
    #[test]
    fn an_update_survives_the_wire_including_its_empty_rdata() {
        // §2.4.1 RRset exists (value independent) and §2.4.3 RRset does not
        // exist; then §2.5.2 delete an RRset, and one ordinary §2.5.1 add so the
        // message is not made only of the interesting case.
        let prerequisites = vec![
            rr("www.example.com.", Class::new(255), Ttl::ZERO, bare(rt::A)),
            rr("new.example.com.", Class::new(254), Ttl::ZERO, bare(rt::A)),
        ];
        let changes = vec![
            rr("old.example.com.", Class::new(255), Ttl::ZERO, bare(rt::A)),
            rr(
                "add.example.com.",
                Class::new(1),
                Ttl::from_secs(3600),
                a("192.0.2.7"),
            ),
        ];

        let message = update(prerequisites, changes);
        let mut buf = vec![0u8; 4096];
        let n = message.to_bytes(&mut buf).expect("an UPDATE serializes");
        let back = DnsMessage::try_from_bytes(&buf[..n])
            .expect("and reads back — RFC 2136 §2.4/§2.5 records carry RDLENGTH=0");

        let request = parse(&back).expect("and is a well-formed UPDATE");
        assert_eq!(
            request.prerequisites,
            vec![
                Prerequisite::RrsetExists {
                    name: "www.example.com.".to_string(),
                    rtype: rt::A,
                },
                Prerequisite::RrsetDoesNotExist {
                    name: "new.example.com.".to_string(),
                    rtype: rt::A,
                },
            ],
            "the forms survive the round trip, not just the bytes"
        );
        assert_eq!(
            request.changes[0],
            Change::DeleteRrset {
                name: "old.example.com.".to_string(),
                rtype: rt::A,
            }
        );
        assert!(matches!(request.changes[1], Change::Add(_)));
    }

    /// §3.4.1 forbids adding a meta-type, and §2.4 requires a zero TTL on every
    /// prerequisite. Both are FORMERR, and both are the kind of thing a
    /// hand-built message gets wrong.
    #[test]
    fn a_meta_type_may_not_be_added_and_a_prerequisite_may_not_carry_a_ttl() {
        // TYPE=ANY with CLASS=the zone's is §2.5.1's "add", and ANY is a
        // meta-type, so §3.4.1's prescan must refuse it. Built through the
        // checked constructor rather than by reaching into the record after the
        // fact: ANY has no decoder, so the bytes are opaque and kept verbatim,
        // which is what a meta-type in a TYPE field is.
        let add_any = rr(
            "www.example.com.",
            Class::new(1),
            Ttl::from_secs(3600),
            RecordData::new(rt::ANY, vec![192, 0, 2, 50]).expect("opaque rdata"),
        );
        assert_eq!(
            parse(&update(Vec::new(), vec![add_any])).unwrap_err().rcode,
            ResponseCode::FormatError,
            "adding TYPE=ANY"
        );

        let ttl_on_prerequisite = rr(
            "www.example.com.",
            Class::new(255),
            Ttl::from_secs(3600),
            bare(rt::A),
        );
        assert_eq!(
            parse(&update(vec![ttl_on_prerequisite], Vec::new()))
                .unwrap_err()
                .rcode,
            ResponseCode::FormatError,
            "a prerequisite with a non-zero TTL"
        );
    }

    /// §3.2's four rcodes, each from the prerequisite form that produces it.
    ///
    /// They are not interchangeable and that is the point of the test: a client
    /// distinguishes "the name is not there" (NXDOMAIN) from "the name is there
    /// and this type is not" (NXRRSET), and an implementation that collapsed
    /// them would still pass a test that only checked for failure.
    #[test]
    fn each_prerequisite_failure_has_its_own_rcode() {
        let zone = zone();

        let cases = vec![
            (
                Prerequisite::RrsetExists {
                    name: "www.example.com.".to_string(),
                    rtype: rt::TXT,
                },
                ResponseCode::NoSuchResourceRecordSet,
                "§3.2.1 NXRRSET: the name is there, the type is not",
            ),
            (
                Prerequisite::RrsetDoesNotExist {
                    name: "www.example.com.".to_string(),
                    rtype: rt::A,
                },
                ResponseCode::ResourceRecordSetExistsForSomeReason,
                "§3.2.2 YXRRSET: it does exist",
            ),
            (
                Prerequisite::NameInUse {
                    name: "nope.example.com.".to_string(),
                },
                ResponseCode::NoSuchDomain,
                "§3.2.4 NXDOMAIN: no such name",
            ),
            (
                Prerequisite::NameNotInUse {
                    name: "www.example.com.".to_string(),
                },
                ResponseCode::DomainExistsForSomeReason,
                "§3.2.5 YXDOMAIN: the name is in use",
            ),
        ];

        for (prerequisite, rcode, what) in cases {
            let outcome = check_prerequisites(&zone, &[prerequisite]);
            assert_eq!(outcome.unwrap_err().rcode, rcode, "{what}");
        }
    }

    /// The ones that hold, so the test above is not passing because everything
    /// fails.
    #[test]
    fn prerequisites_that_hold_are_accepted() {
        let zone = zone();
        check_prerequisites(
            &zone,
            &[
                Prerequisite::RrsetExists {
                    name: "www.example.com.".to_string(),
                    rtype: rt::A,
                },
                Prerequisite::RrsetDoesNotExist {
                    name: "www.example.com.".to_string(),
                    rtype: rt::TXT,
                },
                Prerequisite::NameInUse {
                    name: "ns1.example.com.".to_string(),
                },
                Prerequisite::NameNotInUse {
                    name: "nope.example.com.".to_string(),
                },
            ],
        )
        .expect("every one of these holds against the test zone");
    }

    /// §3.2.3 compares a value-dependent prerequisite against the **whole**
    /// RRset, as a set.
    ///
    /// `www` has two A records. A prerequisite naming one of them must fail,
    /// and naming both must pass whatever order they arrive in. An
    /// implementation that checked "is this record present" rather than "is the
    /// RRset exactly this" would pass the first case wrongly — and that is the
    /// bug this test exists for, because "contains" is the obvious reading and
    /// the RFC does not say it.
    #[test]
    fn a_value_dependent_prerequisite_compares_the_whole_rrset() {
        let zone = zone();
        let name = "www.example.com.".to_string();

        let one_of_two = Prerequisite::RrsetExistsWithValue {
            name: name.clone(),
            rtype: rt::A,
            rdatas: vec![a("192.0.2.10")],
        };
        assert_eq!(
            check_prerequisites(&zone, &[one_of_two]).unwrap_err().rcode,
            ResponseCode::NoSuchResourceRecordSet,
            "naming one record of a two-record RRset is not a match"
        );

        // Both, in the other order: still a match, because §3.2.3 is set
        // comparison and an RRset has no order (RFC 2181 §5).
        let both_reversed = Prerequisite::RrsetExistsWithValue {
            name: name.clone(),
            rtype: rt::A,
            rdatas: vec![a("192.0.2.11"), a("192.0.2.10")],
        };
        check_prerequisites(&zone, &[both_reversed]).expect("both records, either order");

        // A record the RRset does not hold at all, alongside one it does.
        let wrong_member = Prerequisite::RrsetExistsWithValue {
            name,
            rtype: rt::A,
            rdatas: vec![a("192.0.2.10"), a("192.0.2.99")],
        };
        assert_eq!(
            check_prerequisites(&zone, &[wrong_member])
                .unwrap_err()
                .rcode,
            ResponseCode::NoSuchResourceRecordSet
        );
    }

    /// The same RRset arriving as several records is one prerequisite, which is
    /// how it looks on the wire: §2.4.2 has no way to say "and these belong
    /// together" other than sharing a name and type.
    #[test]
    fn value_dependent_records_sharing_a_name_and_type_are_one_prerequisite() {
        let zone = zone();
        let message = update(
            vec![
                rr(
                    "www.example.com.",
                    Class::new(1),
                    Ttl::from_secs(0),
                    a("192.0.2.10"),
                ),
                rr(
                    "www.example.com.",
                    Class::new(1),
                    Ttl::from_secs(0),
                    a("192.0.2.11"),
                ),
            ],
            Vec::new(),
        );
        let parsed = parse(&message).expect("two records, one RRset");
        assert_eq!(parsed.prerequisites.len(), 2, "two on the wire");
        check_prerequisites(&zone, &parsed.prerequisites)
            .expect("but one prerequisite, and it matches the whole RRset");
    }

    /// A name a wildcard would answer for is not a name that is *in use*.
    ///
    /// `Zone::name_exists` is true for a name a wildcard reaches and for an
    /// empty non-terminal; `holds_name` is the literal "are there records here".
    /// §2.4.4 asks the literal question, and getting this wrong would let an
    /// update believe a name exists because something could synthesize it —
    /// then delete or overwrite on the strength of it.
    #[test]
    fn a_wildcard_does_not_make_a_name_in_use() {
        let zone = parse_zone_file(
            "$ORIGIN example.com.\n\
             $TTL 3600\n\
             @ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
             @ IN NS  ns1.example.com.\n\
             * IN A   192.0.2.99\n\
             deep.a.b IN TXT \"down here\"\n",
            "example.com.",
        )
        .expect("the wildcard zone parses");

        // The wildcard answers for it, but nothing is *at* it.
        assert!(!zone
            .query("anything.example.com.", Qtype::of(rt::A))
            .is_empty());
        assert_eq!(
            check_prerequisites(
                &zone,
                &[Prerequisite::NameInUse {
                    name: "anything.example.com.".to_string(),
                }]
            )
            .unwrap_err()
            .rcode,
            ResponseCode::NoSuchDomain,
            "a wildcard answering for a name does not put records at it"
        );

        // An empty non-terminal is the same story from the other side: `a.b`
        // exists in the DNS sense because something is below it, and holds
        // nothing itself.
        assert_eq!(
            check_prerequisites(
                &zone,
                &[Prerequisite::NameInUse {
                    name: "a.b.example.com.".to_string(),
                }]
            )
            .unwrap_err()
            .rcode,
            ResponseCode::NoSuchDomain,
            "an empty non-terminal holds no RRs"
        );
    }

    /// An UPDATE with nothing in it is well-formed and asks for nothing. Worth
    /// pinning: it is the degenerate case a prescan can easily reject by
    /// accident, and RFC 2136 gives no reason to.
    #[test]
    fn an_empty_update_is_well_formed() {
        let parsed = parse(&update(Vec::new(), Vec::new())).expect("no prerequisites, no changes");
        assert_eq!(parsed.zone, "example.com.");
        assert!(parsed.prerequisites.is_empty() && parsed.changes.is_empty());
        check_prerequisites(&zone(), &parsed.prerequisites).expect("nothing to check");
    }

    /// Anything that is not an UPDATE does not go through here at all.
    #[test]
    fn a_query_is_not_an_update() {
        let mut query = update(Vec::new(), Vec::new());
        query.opcode = OpCode::Query;
        assert_eq!(parse(&query).unwrap_err().rcode, ResponseCode::FormatError);
    }
}
