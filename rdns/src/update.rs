//! Dynamic update (RFC 2136): reading an UPDATE, and applying what it asks for.
//!
//! **What this module does and does not do.** It turns an UPDATE message into a
//! checked list of prerequisites and changes, evaluates the prerequisites
//! against a zone, and applies the changes to produce a new zone — carrying the
//! serial forward as §3.6 requires. It still never touches a file, looks at a
//! TSIG key, or decides who may update what. That seam is deliberate:
//! `TODO.md` #10 lists six things dynamic UPDATE drags in — the prerequisite
//! language, per-zone authorization, serial handling that collides with
//! re-signing (#8), incremental re-signing, writing the zone back out, and the
//! journal (#7 step 6) — and says they must not be designed separately. What is
//! left on the far side of this module is the *persistence and policy* half.
//! What it produces is also the shape a journal entry and an IXFR delta both
//! want.
//!
//! **The serial is settled here, and it composes with #8 rather than fighting
//! it.** An UPDATE moves the zone's own serial by one (§3.6); signing serves
//! `file_serial + hours-since-epoch` ([`crate::zone_signer::signed_serial`]).
//! Because that term is *added* rather than `max`ed — which is the correction
//! #8 recorded from PowerDNS's docs — an UPDATE's `+1` survives signing as a
//! `+1` in the served number, within the same hour and across one. Had signing
//! taken a `max`, every UPDATE inside one hour would have served the same
//! serial and no secondary would ever have fetched the change.
//!
//! The one thing this cannot do for itself: the bumped serial has to be
//! **persisted**, or a reload re-reads the file's older number and the served
//! serial goes backwards — which RFC 1982 makes worse than it sounds, since a
//! secondary reads a lower serial as older and declines to transfer, keeping
//! signatures that are about to expire. That is the write-back item, and the
//! reason the journal exists.
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
use crate::zone::{Zone, ZoneRecord};
use crate::ParsedRecord;
use crate::Qtype;
use crate::Rtype;
use crate::Serial;
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

// ---------------------------------------------------------------------------
// Applying the changes (RFC 2136 §3.4.2)
// ---------------------------------------------------------------------------

/// A change RFC 2136 §3.4.2 required be dropped, and the rule that dropped it.
///
/// **§3.4.2 does not reject these.** Every one of them is a change the RFC says
/// to ignore while the UPDATE as a whole still succeeds — §3.4.2.5 signals
/// NOERROR regardless — so without something like this they vanish: the client
/// is told its write went through, the record is not there, and nothing
/// anywhere says why. That is `CLAUDE.md` §4's silent degradation exactly, and
/// it is why this is carried out rather than counted. `rdnsd` logs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ignored {
    pub name: String,
    pub rtype: Rtype,
    /// The rule, naming the section it comes from, for the log line.
    pub why: &'static str,
}

impl std::fmt::Display for Ignored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.name, self.rtype, self.why)
    }
}

/// What [`apply`] did.
#[derive(Debug, Clone)]
pub struct Applied {
    /// The zone as it now is. Rebuilt, never edited in place — see [`Working`].
    pub zone: Zone,
    /// How many records the zone gained, lost, or had replaced by something
    /// that differs from what was there.
    ///
    /// Zero means the UPDATE was well-formed, permitted, and changed nothing —
    /// which is a real outcome (every deletion named a record that was already
    /// gone) and the one case where the serial deliberately does not move.
    pub changed: usize,
    /// Changes §3.4.2 required be dropped. Empty for the ordinary case.
    pub ignored: Vec<Ignored>,
}

/// Apply an UPDATE's changes to a zone (RFC 2136 §3.4.2), returning the result.
///
/// The prerequisites are *not* checked here — [`check_prerequisites`] is a
/// separate call because §3.2 requires all of them to pass before any of §3.4
/// runs, and splitting the two is what makes that ordering something a caller
/// cannot get wrong by interleaving.
///
/// **The changes are applied in order, each to the result of the last.** That is
/// what §3.4.2.7's pseudocode describes — a loop over the update records
/// mutating the zone — and it is observable: a delete-the-RRset followed by an
/// add at the same name has to leave one record, not the old ones plus one.
///
/// **Nothing here fails.** §3.4.2 has exactly two outcomes for a change that has
/// already passed the prescan: it happens, or it is ignored. The failures §3.4.2
/// does describe are §3.4.2.1's "system failure ... out of memory, or a hardware
/// error in persistent storage", which is not this function's problem, and they
/// are why the caller must not install the result until it has stored it.
///
/// **This is meant for the unsigned source zone**, the one that came from the
/// file and goes back to it. Applying an UPDATE to signer output and then
/// re-signing would be doing the work twice; the signatures over anything this
/// touched are stale by definition.
pub fn apply(zone: &Zone, changes: &[Change]) -> Applied {
    let mut work = Working::new(zone);
    let mut ignored = Vec::new();
    let mut changed = 0usize;
    // Whether the UPDATE itself moved the apex serial, which decides whether
    // §3.6's automatic bump is owed. Set only for the *apex* SOA: an SOA
    // somewhere else in the zone is not the zone's version number.
    let mut serial_moved_by_update = false;

    for change in changes {
        match change {
            Change::Add(record) => {
                let name = work.absolute(&record.name);
                let rtype = record.rdata.rtype();

                // §3.4.2.7: a CNAME may not be added where other data lives,
                // and other data may not be added where a CNAME lives. The
                // underlying rule is RFC 1034 §3.6.2's — a CNAME is the only
                // record at its name — and §3.4.2.7 is where RFC 2136 says an
                // UPDATE must not be the thing that breaks it.
                if rtype == rt::CNAME {
                    if work.has_other_data_beside_a_cname(&name) {
                        ignored.push(Ignored {
                            name,
                            rtype,
                            why: "RFC 2136 §3.4.2.7: a CNAME may not be added \
                                  where other data exists",
                        });
                        continue;
                    }
                } else if work.has_type(&name, rt::CNAME) {
                    ignored.push(Ignored {
                        name,
                        rtype,
                        why: "RFC 2136 §3.4.2.7: data may not be added where a \
                              CNAME exists",
                    });
                    continue;
                }

                // §3.4.2.2: "If the TYPE is SOA and there is no Zone SOA RR, or
                // the new SOA.SERIAL is lower (according to [RFC1982]) than or
                // equal to the current Zone SOA RR's SOA.SERIAL, the Update RR
                // is ignored."
                //
                // **The prose and the pseudocode disagree here, and the prose
                // wins.** §3.4.2.7 spells the test as `zone.serial > rr.serial`
                // — which *accepts* an equal serial — while the paragraph above
                // ignores "lower than or equal to". Following the pseudocode
                // would let an UPDATE rewrite MNAME, RNAME or the timers while
                // leaving the version number where it was, and §3.6 calls it
                // "imperative that the zone's contents and the SOA's SERIAL be
                // tightly synchronized". So: strictly newer, or ignored.
                //
                // `is_newer_than` is RFC 1982 §3.2 and not `>` (`CLAUDE.md`
                // §17). It is also false for two serials exactly half the space
                // apart, where §3.2 leaves the answer undefined — ignoring is
                // the safe direction, since the alternative is installing a
                // version nobody can order against the one it replaced.
                if rtype == rt::SOA {
                    let current = work.soa_serial_at(&name);
                    let offered = serial_of(&record.rdata);
                    let acceptable = matches!(
                        (current, offered),
                        (Some(current), Some(offered)) if offered.is_newer_than(current)
                    );
                    if !acceptable {
                        ignored.push(Ignored {
                            name,
                            rtype,
                            why: "RFC 2136 §3.4.2.2: an SOA is ignored unless its \
                                  serial is newer than the one it would replace",
                        });
                        continue;
                    }
                }

                let replacement = ZoneRecord {
                    name: name.clone(),
                    ttl: record.ttl,
                    class: record.class,
                    rdata: record.rdata.clone(),
                };

                // §3.4.2.7's inner loop: within the RRset, a CNAME or an SOA
                // replaces whatever is there — both are singletons, so "add"
                // can only mean "replace" — and anything else replaces only an
                // exact RDATA match. That last case is how an UPDATE changes a
                // TTL: same name, type and value, new number.
                //
                // WKS has a third rule in §3.4.2.2, matching on ADDRESS and
                // PROTOCOL rather than on the whole RDATA. It is not
                // implemented, and cannot be here: this library has no WKS
                // decoder, so a WKS record is opaque RFC 3597 bytes and its
                // address and protocol are not separable from its bitmap. The
                // consequence is bounded and worth stating — two WKS records
                // that share an address and protocol end up side by side
                // instead of one replacing the other.
                match work.position_to_replace(&name, rtype, &record.rdata) {
                    Some(position) => {
                        if !same_record(&work.records[position], &replacement) {
                            changed += 1;
                        }
                        work.records[position] = replacement;
                        if rtype == rt::SOA && work.is_apex(&name) {
                            serial_moved_by_update = true;
                        }
                    }
                    None => {
                        work.records.push(replacement);
                        changed += 1;
                    }
                }
            }

            // §3.4.2.3, second half: "For any Update RR whose CLASS is ANY and
            // whose TYPE is not ANY all Zone RRs with the same NAME and TYPE
            // are deleted, unless the NAME is the same as ZNAME in which case
            // neither SOA or NS RRs will be deleted."
            Change::DeleteRrset { name, rtype } => {
                let name = work.absolute(name);
                if work.is_apex(&name) && (*rtype == rt::SOA || *rtype == rt::NS) {
                    ignored.push(Ignored {
                        name,
                        rtype: *rtype,
                        why: "RFC 2136 §3.4.2.3: the apex SOA and NS RRsets are \
                              not deleted — a zone without them is not a zone",
                    });
                    continue;
                }
                changed += work.remove(|record| {
                    record.name.eq_ignore_ascii_case(&name) && record.rdata.rtype() == *rtype
                });
            }

            // §3.4.2.3, first half: "all Zone RRs with the same NAME are
            // deleted, unless the NAME is the same as ZNAME in which case only
            // those RRs whose TYPE is other than SOA or NS are deleted."
            Change::DeleteName { name } => {
                let name = work.absolute(name);
                let apex = work.is_apex(&name);
                changed += work.remove(|record| {
                    record.name.eq_ignore_ascii_case(&name)
                        && !(apex
                            && (record.rdata.rtype() == rt::SOA || record.rdata.rtype() == rt::NS))
                });
                if apex {
                    // Not a refusal — the rest of the name was emptied — but
                    // the operator asked for the whole name and did not get it.
                    ignored.push(Ignored {
                        name,
                        rtype: rt::ANY,
                        why: "RFC 2136 §3.4.2.3: the apex SOA and NS RRsets \
                              survive a delete-the-whole-name",
                    });
                }
            }

            // §3.4.2.4: "any Zone RR whose NAME, TYPE, RDATA and RDLENGTH are
            // equal to the Update RR is deleted, unless the NAME is the same as
            // ZNAME and either the TYPE is SOA or the TYPE is NS and the
            // matching Zone RR is the only NS remaining in the RRset, in which
            // case this Update RR is ignored."
            //
            // Comparing the whole [`RecordData`] is the "TYPE, RDATA and
            // RDLENGTH" of that sentence in one test: the type is inside it and
            // its bytes are its own length.
            Change::DeleteRecord { name, rtype, rdata } => {
                let name = work.absolute(name);
                if work.is_apex(&name) && *rtype == rt::SOA {
                    ignored.push(Ignored {
                        name,
                        rtype: *rtype,
                        why: "RFC 2136 §3.4.2.4: the apex SOA is not deleted",
                    });
                    continue;
                }
                // "the only NS remaining in the RRset" — so the test is whether
                // this deletion would empty the apex NS RRset, not whether the
                // RRset is currently a singleton. A deletion naming a record
                // the zone does not hold empties nothing and is not refused.
                if work.is_apex(&name) && *rtype == rt::NS {
                    let held = work.count(&name, rt::NS);
                    let matching = work.count_matching(&name, rdata);
                    if matching > 0 && held == matching {
                        ignored.push(Ignored {
                            name,
                            rtype: *rtype,
                            why: "RFC 2136 §3.4.2.4: the last apex NS is not \
                                  deleted",
                        });
                        continue;
                    }
                }
                changed += work.remove(|record| {
                    record.name.eq_ignore_ascii_case(&name) && record.rdata == *rdata
                });
            }
        }
    }

    // RFC 2136 §3.6. The serial has to move for the change to be visible: a
    // secondary decides whether to transfer by comparing it, so contents that
    // moved under an unchanged serial are contents no replica will ever fetch.
    //
    // **Only when something actually changed**, which is the reading §3.6's own
    // wording gives — the bump is owed "prior to including the SOA or any
    // modified resource records in responses or zone transfers", and an UPDATE
    // that modified nothing has none. The alternative costs real work for
    // nothing: a serial bump is a re-signing run and an IXFR to every
    // secondary, and an UPDATE whose deletions all named records that were
    // already gone is an ordinary thing for a DHCP client to send twice.
    if changed > 0 && !serial_moved_by_update {
        work.bump_serial();
    }

    Applied {
        zone: work.into_zone(),
        changed,
        ignored,
    }
}

/// The zone as it is being rewritten.
///
/// **A `Vec` rather than a [`Zone`], and the reason is the same one
/// [`crate::ixfr::apply_changes`] gives**: `Zone`'s index holds *positions* into
/// its record vector, so removing a record in place shifts every later position
/// and invalidates it. That is why `Zone` has no removal API and should never
/// get one. Rebuilding at the end costs O(zone) per UPDATE rather than per
/// change, and hands back a zone built by the ordinary constructor — one whose
/// index cannot disagree with its contents.
///
/// It borrows the zone it started from rather than copying the origin, so that
/// [`Working::absolute`] is [`Zone::normalize_name`] and not a second
/// hand-written copy of what an owner name means (`CLAUDE.md` §7).
struct Working<'a> {
    base: &'a Zone,
    records: Vec<ZoneRecord>,
}

impl<'a> Working<'a> {
    fn new(base: &'a Zone) -> Working<'a> {
        Working {
            // Names are normalized on the way in so that every comparison below
            // is one `eq_ignore_ascii_case` and not a normalization per record
            // per change. A zone loaded from a file already holds absolute
            // names; one built by hand through `add_record` may not.
            records: base
                .records()
                .iter()
                .map(|record| ZoneRecord {
                    name: base.normalize_name(&record.name).into_owned(),
                    ttl: record.ttl,
                    class: record.class,
                    rdata: record.rdata.clone(),
                })
                .collect(),
            base,
        }
    }

    fn absolute(&self, name: &str) -> String {
        self.base.normalize_name(name).into_owned()
    }

    fn is_apex(&self, name: &str) -> bool {
        name.eq_ignore_ascii_case(self.base.origin())
    }

    fn has_type(&self, name: &str, rtype: Rtype) -> bool {
        self.records
            .iter()
            .any(|r| r.name.eq_ignore_ascii_case(name) && r.rdata.rtype() == rtype)
    }

    /// Whether the name holds anything that RFC 1034 §3.6.2 would call "other
    /// data" beside a CNAME.
    ///
    /// RRSIG, NSEC and NSEC3 are excluded, because RFC 4035 §2.5 says outright
    /// that a CNAME may carry them at the same owner name — they are the one
    /// exception to §3.6.2. Without this, an UPDATE replacing a CNAME in a zone
    /// that had been signed would be ignored on the strength of the signature
    /// over the CNAME it was replacing.
    ///
    /// Deliberately *not* `zone_signer::is_signer_output`, which answers a
    /// different question — "would signing regenerate this" — and includes
    /// NSEC3PARAM and DNSKEY, neither of which has anything to do with §3.6.2.
    /// Two predicates that happen to overlap are not one predicate (§7's
    /// converse: move logic when the *reason* is shared, not when the answer
    /// coincides).
    fn has_other_data_beside_a_cname(&self, name: &str) -> bool {
        self.records.iter().any(|r| {
            r.name.eq_ignore_ascii_case(name)
                && !matches!(
                    r.rdata.rtype(),
                    rt::CNAME | rt::RRSIG | rt::NSEC | rt::NSEC3
                )
        })
    }

    fn count(&self, name: &str, rtype: Rtype) -> usize {
        self.records
            .iter()
            .filter(|r| r.name.eq_ignore_ascii_case(name) && r.rdata.rtype() == rtype)
            .count()
    }

    fn count_matching(&self, name: &str, rdata: &RecordData) -> usize {
        self.records
            .iter()
            .filter(|r| r.name.eq_ignore_ascii_case(name) && r.rdata == *rdata)
            .count()
    }

    /// Which record this add replaces, per §3.4.2.7's inner loop, or `None` if
    /// it joins the RRset instead.
    fn position_to_replace(&self, name: &str, rtype: Rtype, rdata: &RecordData) -> Option<usize> {
        self.records.iter().position(|r| {
            r.name.eq_ignore_ascii_case(name)
                && r.rdata.rtype() == rtype
                && (rtype == rt::CNAME || rtype == rt::SOA || r.rdata == *rdata)
        })
    }

    /// Drop every record the predicate is true of, reporting how many went.
    fn remove(&mut self, doomed: impl Fn(&ZoneRecord) -> bool) -> usize {
        let before = self.records.len();
        self.records.retain(|record| !doomed(record));
        before - self.records.len()
    }

    /// The serial of the SOA at `name`, if there is one that can be read.
    fn soa_serial_at(&self, name: &str) -> Option<Serial> {
        self.records
            .iter()
            .find(|r| r.name.eq_ignore_ascii_case(name) && r.rdata.rtype() == rt::SOA)
            .and_then(|r| serial_of(&r.rdata))
    }

    /// RFC 2136 §3.6's automatic increment, applied to the apex SOA.
    ///
    /// `wrapping_add`, because RFC 1982 §3.1 defines addition in the sequence
    /// space that way — the serial after `u32::MAX` is 0, and a bare `+` would
    /// panic in a debug build at the one moment it mattered.
    ///
    /// Re-encoding the SOA through [`ParsedRecord`] is exact for this type: its
    /// two names are written uncompressed both times, so the bytes that come
    /// back differ only in the four the serial occupies. That matters because
    /// re-spelling RDATA is how a valid RRset silently becomes a bogus one
    /// (`zone_writer`'s module docs), and it is the reason this rewrites the one
    /// record it must rather than passing the whole zone through a re-encode.
    fn bump_serial(&mut self) {
        let origin = self.base.origin().to_string();
        for record in &mut self.records {
            if record.rdata.rtype() != rt::SOA || !record.name.eq_ignore_ascii_case(&origin) {
                continue;
            }
            let Ok(ParsedRecord::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }) = record.rdata.parse()
            else {
                // An apex SOA whose RDATA will not parse is a zone that could
                // not have been loaded, served or transferred; there is nothing
                // to bump and nothing this function can do about it.
                continue;
            };
            let bumped = ParsedRecord::SOA {
                mname,
                rname,
                serial: serial.wrapping_add(1),
                refresh,
                retry,
                expire,
                minimum,
            };
            if let Ok(rdata) = RecordData::from_parsed(&bumped) {
                record.rdata = rdata;
            }
            return;
        }
    }

    fn into_zone(self) -> Zone {
        let mut zone = Zone::new(self.base.origin().to_string());
        for record in self.records {
            zone.add_record(record);
        }
        zone
    }
}

/// Whether a replacement would leave the record it replaces unchanged.
///
/// The TTL counts, which is the same identity [`crate::ixfr::diff`] compares by
/// and for the same reason: two records differing only in TTL are not the same
/// record to a secondary, because it caches and re-serves that number. The name
/// is not compared — the caller found this record *by* name.
fn same_record(held: &ZoneRecord, replacement: &ZoneRecord) -> bool {
    held.ttl == replacement.ttl
        && held.class == replacement.class
        && held.rdata == replacement.rdata
}

/// The serial inside an SOA's RDATA, if it is one and it parses.
fn serial_of(rdata: &RecordData) -> Option<Serial> {
    match rdata.parse() {
        Ok(ParsedRecord::SOA { serial, .. }) => Some(serial),
        _ => None,
    }
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

    // -----------------------------------------------------------------
    // Applying (RFC 2136 §3.4.2)
    // -----------------------------------------------------------------

    /// An SOA that is distinguishable from the test zone's by something other
    /// than its serial.
    ///
    /// The different RNAME is load-bearing, not decoration. The zone's serial is
    /// 1, so an offered SOA at serial 1 leaves the zone's serial at 1 whether it
    /// was accepted or ignored — a test asserting on the serial alone cannot
    /// tell the two apart, and would pass against an implementation with no
    /// serial check in it at all. Asserting on the whole RDATA can, and the
    /// equal-serial case is precisely "rewriting RNAME while leaving the version
    /// where it was", which is what §3.4.2.2's prose forbids.
    fn soa_with(serial: u32) -> RecordData {
        RecordData::from_parsed(&ParsedRecord::SOA {
            mname: "ns1.example.com.".to_string(),
            rname: "hostmaster.example.com.".to_string(),
            serial: Serial::new(serial),
            refresh: 3600,
            retry: 600,
            expire: 604800,
            minimum: 300,
        })
        .expect("an SOA encodes")
    }

    fn ns(target: &str) -> RecordData {
        RecordData::from_parsed(&ParsedRecord::NS(target.to_string())).expect("an NS encodes")
    }

    fn cname(target: &str) -> RecordData {
        RecordData::from_parsed(&ParsedRecord::CNAME(target.to_string())).expect("a CNAME encodes")
    }

    /// How many records of a type sit at a name, counted from the zone's own
    /// index rather than by scanning — so the rebuilt zone is checked through
    /// the API a query uses, not through the vector `apply` happened to build.
    fn held(zone: &Zone, name: &str, rtype: Rtype) -> usize {
        zone.query(name, Qtype::of(rtype)).len()
    }

    fn add(name: &str, ttl: u32, rdata: RecordData) -> Change {
        Change::Add(rr(name, Class::new(1), Ttl::from_secs(ttl), rdata))
    }

    /// All four update forms of §2.5, applied — the mirror of
    /// [`the_four_update_forms_are_read_as_rfc_2136_defines_them`], which
    /// checked only that they were *read*.
    #[test]
    fn the_four_update_forms_change_the_zone_as_rfc_2136_describes() {
        let zone = zone();

        // §2.5.1 add: a new name, and a second record joining an existing
        // RRset.
        let applied = apply(
            &zone,
            &[
                add("new.example.com.", 3600, a("192.0.2.50")),
                add("www.example.com.", 3600, a("192.0.2.12")),
            ],
        );
        assert_eq!(applied.changed, 2);
        assert_eq!(held(&applied.zone, "new.example.com.", rt::A), 1);
        assert_eq!(
            held(&applied.zone, "www.example.com.", rt::A),
            3,
            "an add joins the RRset rather than replacing it"
        );

        // §2.5.2 delete an RRset: both of www's A records go, and nothing else
        // at the name does.
        let applied = apply(
            &zone,
            &[Change::DeleteRrset {
                name: "www.example.com.".to_string(),
                rtype: rt::A,
            }],
        );
        assert_eq!(applied.changed, 2, "both records of the RRset");
        assert_eq!(held(&applied.zone, "www.example.com.", rt::A), 0);
        assert_eq!(held(&applied.zone, "mail.example.com.", rt::MX), 1);

        // §2.5.3 delete every RRset at a name.
        let applied = apply(
            &zone,
            &[Change::DeleteName {
                name: "mail.example.com.".to_string(),
            }],
        );
        assert!(!applied.zone.holds_name("mail.example.com."));
        assert!(applied.ignored.is_empty(), "not the apex");

        // §2.5.4 delete one record, leaving its RRset-mate behind.
        let applied = apply(
            &zone,
            &[Change::DeleteRecord {
                name: "www.example.com.".to_string(),
                rtype: rt::A,
                rdata: a("192.0.2.11"),
            }],
        );
        assert_eq!(applied.changed, 1);
        let left = applied.zone.query("www.example.com.", Qtype::of(rt::A));
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].rdata, a("192.0.2.10"), "the other one survived");
    }

    /// **§3.4.2.3 and §3.4.2.4's apex protections, all three of them.**
    ///
    /// > unless the NAME is the same as ZNAME in which case only those RRs
    /// > whose TYPE is other than SOA or NS are deleted
    ///
    /// A zone that deleted its own SOA and apex NS would stop being a zone: it
    /// could not be transferred (both `axfr_messages` and `ixfr_response` fail
    /// without an apex SOA), could not report a serial, and would answer for a
    /// delegation it no longer holds. This is the rule a straightforward
    /// `retain` gets wrong, because the obvious implementation of "delete every
    /// RRset at this name" deletes every RRset at that name.
    ///
    /// **Watched failing** against a `Change::DeleteName` arm written without
    /// the `apex &&` guard: the SOA and the NS both went, `applied.zone.serial()`
    /// came back `None`, and the first assertion below fired.
    #[test]
    fn the_apex_soa_and_ns_survive_every_form_of_deletion() {
        let zone = zone();
        let apex = "example.com.";

        // §3.4.2.3 first half — delete the whole apex name.
        let applied = apply(
            &zone,
            &[Change::DeleteName {
                name: apex.to_string(),
            }],
        );
        assert_eq!(
            applied.zone.serial(),
            Some(Serial::new(1)),
            "the apex SOA survives, and unbumped: nothing was deleted"
        );
        assert_eq!(held(&applied.zone, apex, rt::NS), 1, "and the apex NS");
        assert_eq!(
            applied.changed, 0,
            "the apex held only its SOA and NS, so nothing went"
        );
        assert_eq!(
            applied.ignored.len(),
            1,
            "and the operator is told the name was not emptied"
        );

        // §3.4.2.3 second half — delete the apex SOA or NS RRset by name.
        for rtype in [rt::SOA, rt::NS] {
            let applied = apply(
                &zone,
                &[Change::DeleteRrset {
                    name: apex.to_string(),
                    rtype,
                }],
            );
            assert_eq!(held(&applied.zone, apex, rtype), 1, "{rtype} at the apex");
            assert_eq!(applied.changed, 0);
            assert_eq!(applied.ignored.len(), 1, "{rtype}");
        }

        // §3.4.2.4 — delete the apex SOA as a specific record.
        let applied = apply(
            &zone,
            &[Change::DeleteRecord {
                name: apex.to_string(),
                rtype: rt::SOA,
                rdata: zone.query(apex, Qtype::of(rt::SOA))[0].rdata.clone(),
            }],
        );
        assert_eq!(applied.zone.serial(), Some(Serial::new(1)));
        assert_eq!(applied.changed, 0);
    }

    /// §3.4.2.4 protects "the only NS remaining in the RRset" — which is a
    /// question about what the deletion would *leave*, not about whether the
    /// RRset is a singleton now.
    ///
    /// Both halves, because an implementation that refused whenever the apex had
    /// one NS would pass the first and an implementation that never refused
    /// would pass the second. The two-NS zone is the case that separates them.
    #[test]
    fn the_last_apex_ns_is_not_deleted_but_one_of_two_is() {
        let two_ns = parse_zone_file(
            "$ORIGIN example.com.\n\
             $TTL 3600\n\
             @ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
             @ IN NS  ns1.example.com.\n\
             @ IN NS  ns2.example.com.\n",
            "example.com.",
        )
        .expect("the two-NS zone parses");

        let delete_one = |zone: &Zone, target: &str| {
            apply(
                zone,
                &[Change::DeleteRecord {
                    name: "example.com.".to_string(),
                    rtype: rt::NS,
                    rdata: ns(target),
                }],
            )
        };

        // Two there: one may go.
        let applied = delete_one(&two_ns, "ns2.example.com.");
        assert_eq!(applied.changed, 1);
        assert_eq!(held(&applied.zone, "example.com.", rt::NS), 1);
        assert!(applied.ignored.is_empty());

        // One left: it may not.
        let last = delete_one(&applied.zone, "ns1.example.com.");
        assert_eq!(held(&last.zone, "example.com.", rt::NS), 1);
        assert_eq!(last.changed, 0);
        assert_eq!(last.ignored.len(), 1);

        // And a deletion naming an NS the zone does not hold is not refused —
        // it simply matches nothing. Refusing here would report a protection
        // that did not protect anything.
        let absent = delete_one(&applied.zone, "ns9.elsewhere.test.");
        assert_eq!(absent.changed, 0);
        assert!(
            absent.ignored.is_empty(),
            "nothing matched, so nothing was protected: {:?}",
            absent.ignored
        );
    }

    /// §3.4.2.7: a CNAME may not be added where other data lives, and other
    /// data may not be added where a CNAME lives.
    ///
    /// The underlying rule is RFC 1034 §3.6.2's — a CNAME is alone at its name —
    /// and the reason it is restated in RFC 2136 is that an UPDATE is the one
    /// thing that can create the situation after the zone file has been read.
    ///
    /// The third case is the exception RFC 4035 §2.5 carves out: RRSIG, NSEC and
    /// NSEC3 *may* sit beside a CNAME, so a signed zone must not become one
    /// whose CNAMEs can never be updated again.
    #[test]
    fn a_cname_and_other_data_never_join_at_one_name() {
        let zone = zone();

        // A CNAME where two A records live.
        let applied = apply(
            &zone,
            &[add("www.example.com.", 3600, cname("elsewhere.test."))],
        );
        assert_eq!(applied.changed, 0);
        assert_eq!(held(&applied.zone, "www.example.com.", rt::CNAME), 0);
        assert_eq!(applied.ignored.len(), 1);

        // And the other way round: an A where a CNAME lives.
        let with_cname = apply(
            &zone,
            &[add("alias.example.com.", 3600, cname("www.example.com."))],
        );
        assert_eq!(with_cname.changed, 1);
        let applied = apply(
            &with_cname.zone,
            &[add("alias.example.com.", 3600, a("192.0.2.77"))],
        );
        assert_eq!(applied.changed, 0);
        assert_eq!(held(&applied.zone, "alias.example.com.", rt::A), 0);

        // A CNAME replacing a CNAME is the ordinary case and must still work —
        // §3.4.2.7 replaces rather than appends for this type.
        let applied = apply(
            &with_cname.zone,
            &[add("alias.example.com.", 3600, cname("mail.example.com."))],
        );
        assert_eq!(
            held(&applied.zone, "alias.example.com.", rt::CNAME),
            1,
            "one CNAME, not two"
        );
        assert_eq!(
            applied
                .zone
                .query("alias.example.com.", Qtype::of(rt::CNAME))[0]
                .rdata,
            cname("mail.example.com.")
        );

        // RFC 4035 §2.5: an RRSIG beside the CNAME is not "other data", so the
        // replacement above still goes through when the name has been signed.
        let mut signed = with_cname.zone.clone();
        signed.add_record(ZoneRecord {
            name: "alias.example.com.".to_string(),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::new(rt::RRSIG, vec![0u8; 20]).expect("opaque rdata"),
        });
        let applied = apply(
            &signed,
            &[add("alias.example.com.", 3600, cname("ns1.example.com."))],
        );
        assert_eq!(
            applied.changed, 1,
            "a signature over a CNAME does not freeze it: {:?}",
            applied.ignored
        );
    }

    /// §3.4.2.2: an SOA in the Update section is ignored unless its serial is
    /// newer.
    ///
    /// > If the TYPE is SOA and there is no Zone SOA RR, or the new SOA.SERIAL
    /// > is lower (according to [RFC1982]) than or equal to the current Zone SOA
    /// > RR's SOA.SERIAL, the Update RR is ignored.
    ///
    /// **The equal case is the one worth pinning**, because §3.4.2.7's
    /// pseudocode spells the same test as `zone.serial > rr.serial` — which
    /// accepts an equal serial and would let an UPDATE rewrite MNAME, RNAME or
    /// the timers while leaving the version number where it was. The prose is
    /// the normative text and §3.6 backs it: "imperative that the zone's
    /// contents and the SOA's SERIAL be tightly synchronized".
    ///
    /// And the comparison is RFC 1982's, so a serial that has wrapped past the
    /// 32-bit ceiling is newer than the large number it followed. A `>` reads
    /// that as a rollback and refuses the update forever after.
    #[test]
    fn an_soa_is_ignored_unless_its_serial_is_newer() {
        let zone = zone();

        let original = zone.query("example.com.", Qtype::of(rt::SOA))[0]
            .rdata
            .clone();

        for (offered, accepted, what) in [
            (1, false, "equal to the current serial"),
            (0, false, "lower than the current serial"),
            (2, true, "newer"),
        ] {
            let applied = apply(&zone, &[add("example.com.", 3600, soa_with(offered))]);
            let installed = applied.zone.query("example.com.", Qtype::of(rt::SOA))[0]
                .rdata
                .clone();
            if accepted {
                assert_eq!(installed, soa_with(offered), "{what}");
                assert_eq!(applied.changed, 1);
                assert!(applied.ignored.is_empty());
            } else {
                assert_eq!(
                    installed, original,
                    "an SOA serial {offered} is {what}, so the whole record stays"
                );
                assert_eq!(applied.changed, 0);
                assert_eq!(applied.ignored.len(), 1, "{what}");
            }
        }

        // RFC 1982 §3.1's wrap: 0 follows u32::MAX, and is newer than it.
        let at_ceiling = parse_zone_file(
            &format!(
                "$ORIGIN example.com.\n$TTL 3600\n\
                 @ IN SOA ns1.example.com. admin.example.com. ( {} 3600 600 604800 300 )\n\
                 @ IN NS ns1.example.com.\n",
                u32::MAX
            ),
            "example.com.",
        )
        .expect("a zone at the serial ceiling parses");
        let applied = apply(&at_ceiling, &[add("example.com.", 3600, soa_with(0))]);
        assert_eq!(
            applied.zone.serial(),
            Some(Serial::new(0)),
            "0 is newer than u32::MAX in RFC 1982's sequence space"
        );
    }

    /// §3.4.2.2: "In case of duplicate RDATAs ... the Zone RR is replaced by
    /// Update RR."
    ///
    /// So adding a record the zone already holds is how an UPDATE changes a
    /// TTL — and it must not leave two copies of the record behind, which is
    /// what an implementation that only ever appends would do. The count is the
    /// assertion, because the TTL change alone would pass either way.
    #[test]
    fn adding_a_record_that_is_already_there_replaces_it_rather_than_doubling_it() {
        let zone = zone();
        let applied = apply(&zone, &[add("www.example.com.", 60, a("192.0.2.10"))]);

        assert_eq!(
            held(&applied.zone, "www.example.com.", rt::A),
            2,
            "still two records, not three"
        );
        let changed_one = applied
            .zone
            .query("www.example.com.", Qtype::of(rt::A))
            .into_iter()
            .find(|r| r.rdata == a("192.0.2.10"))
            .expect("the record is still there");
        assert_eq!(changed_one.ttl, Ttl::from_secs(60), "with the new TTL");
        assert_eq!(applied.changed, 1);

        // The same record with the same TTL is not a change at all, which is
        // what keeps a retried UPDATE from bumping the serial (see §3.6 below).
        let again = apply(
            &applied.zone,
            &[add("www.example.com.", 60, a("192.0.2.10"))],
        );
        assert_eq!(again.changed, 0);
        assert_eq!(again.zone.serial(), applied.zone.serial());
    }

    /// **RFC 2136 §3.6: the serial moves when the contents move, and not
    /// otherwise.**
    ///
    /// > It is imperative that the zone's contents and the SOA's SERIAL be
    /// > tightly synchronized.
    ///
    /// Both directions matter and they fail in opposite ways. Without the bump,
    /// a secondary compares serials, sees no change, and never fetches the
    /// records that did change — the zone is edited on the primary and nowhere
    /// else. With an unconditional bump, an UPDATE whose deletions all named
    /// records that were already gone — an ordinary thing for a DHCP client to
    /// send twice — costs a re-signing run and an IXFR to every secondary for
    /// nothing.
    ///
    /// **Watched failing** against a `changed > 0 &&` that was not there: the
    /// no-op case below came back at serial 2.
    #[test]
    fn the_serial_moves_by_one_when_something_changed_and_not_when_nothing_did() {
        let zone = zone();
        assert_eq!(zone.serial(), Some(Serial::new(1)));

        let applied = apply(&zone, &[add("new.example.com.", 3600, a("192.0.2.50"))]);
        assert_eq!(applied.changed, 1);
        assert_eq!(applied.zone.serial(), Some(Serial::new(2)));

        // A deletion that names a record the zone does not hold changes
        // nothing, so there is nothing to make visible.
        let no_op = apply(
            &zone,
            &[Change::DeleteRecord {
                name: "www.example.com.".to_string(),
                rtype: rt::A,
                rdata: a("192.0.2.99"),
            }],
        );
        assert_eq!(no_op.changed, 0);
        assert_eq!(
            no_op.zone.serial(),
            Some(Serial::new(1)),
            "nothing changed, so the version did not"
        );

        // An empty UPDATE is the degenerate case of the same thing.
        assert_eq!(apply(&zone, &[]).zone.serial(), Some(Serial::new(1)));

        // An UPDATE that sets the SOA itself owns the number: §3.6's automatic
        // increment is owed only "when the SOA SERIAL is not changed", so this
        // must land on 9 and not 10.
        let explicit = apply(
            &zone,
            &[
                add("example.com.", 3600, soa_with(9)),
                add("new.example.com.", 3600, a("192.0.2.50")),
            ],
        );
        assert_eq!(explicit.zone.serial(), Some(Serial::new(9)));

        // And the bump wraps rather than panicking (RFC 1982 §3.1).
        let at_ceiling = parse_zone_file(
            &format!(
                "$ORIGIN example.com.\n$TTL 3600\n\
                 @ IN SOA ns1.example.com. admin.example.com. ( {} 3600 600 604800 300 )\n\
                 @ IN NS ns1.example.com.\n",
                u32::MAX
            ),
            "example.com.",
        )
        .expect("a zone at the serial ceiling parses");
        let wrapped = apply(
            &at_ceiling,
            &[add("new.example.com.", 3600, a("192.0.2.50"))],
        );
        assert_eq!(wrapped.zone.serial(), Some(Serial::new(0)));
    }

    /// Only the serial moves: the rest of the SOA is the operator's and an
    /// automatic bump must not re-spell it.
    ///
    /// The RDATA is compared byte for byte outside those four octets, because
    /// re-encoding is how a valid RRset silently becomes a bogus one — a
    /// signature covers RDATA exactly, and `zone_writer`'s module docs are about
    /// this same hazard from the other end.
    #[test]
    fn the_automatic_bump_rewrites_four_octets_and_nothing_else() {
        let zone = zone();
        let before = zone.query("example.com.", Qtype::of(rt::SOA))[0]
            .rdata
            .clone();
        let applied = apply(&zone, &[add("new.example.com.", 3600, a("192.0.2.50"))]);
        let after = applied.zone.query("example.com.", Qtype::of(rt::SOA))[0]
            .rdata
            .clone();

        assert_eq!(before.bytes().len(), after.bytes().len());
        let differing: Vec<usize> = before
            .bytes()
            .iter()
            .zip(after.bytes())
            .enumerate()
            .filter(|(_, (b, a))| b != a)
            .map(|(i, _)| i)
            .collect();
        assert!(
            differing.len() <= 4 && differing.windows(2).all(|w| w[1] == w[0] + 1),
            "only the serial's four octets moved, and contiguously: {differing:?}"
        );
    }

    /// §3.4.2.7 is a loop over the update records, each applied to the zone the
    /// last one left. So a delete-then-add at one name leaves exactly what the
    /// add put there.
    ///
    /// An implementation that evaluated every change against the *original*
    /// zone would leave three A records at `www` here instead of one, and would
    /// pass every other test in this file.
    #[test]
    fn changes_apply_in_order_each_to_the_result_of_the_last() {
        let zone = zone();
        let applied = apply(
            &zone,
            &[
                Change::DeleteRrset {
                    name: "www.example.com.".to_string(),
                    rtype: rt::A,
                },
                add("www.example.com.", 300, a("192.0.2.80")),
            ],
        );

        let left = applied.zone.query("www.example.com.", Qtype::of(rt::A));
        assert_eq!(left.len(), 1, "the delete ran first: {left:?}");
        assert_eq!(left[0].rdata, a("192.0.2.80"));

        // And the other order is the other answer: adding into an RRset that is
        // then deleted leaves nothing.
        let reversed = apply(
            &zone,
            &[
                add("www.example.com.", 300, a("192.0.2.80")),
                Change::DeleteRrset {
                    name: "www.example.com.".to_string(),
                    rtype: rt::A,
                },
            ],
        );
        assert_eq!(held(&reversed.zone, "www.example.com.", rt::A), 0);
    }

    /// **The serial an UPDATE writes survives signing** — which is `TODO.md`
    /// #10's "serial handling collides with #8", checked rather than asserted.
    ///
    /// A signed zone does not serve the file's serial: it serves
    /// `file_serial + hours-since-epoch` ([`crate::zone_signer::signed_serial`]).
    /// The question is whether an UPDATE's `+1` is still visible after that term
    /// is applied, because if it is not then no secondary ever fetches an
    /// update made within one hour of the last one.
    ///
    /// It is, and the reason is the correction #8 recorded from PowerDNS's
    /// docs: the time term is **added**, not `max`ed. The `max` version — which
    /// is the obvious design — is included below to show what it would have
    /// cost, and it is not a hypothetical: for any date-style serial the `max`
    /// keeps the file's number, so two updates in one hour would serve one
    /// serial between them.
    #[test]
    fn an_updates_serial_bump_survives_signing() {
        use crate::zone_signer::signed_serial;

        let zone = zone();
        let signed_at = 1_754_200_000u64; // an arbitrary instant, held fixed
        let before = zone.serial().expect("the test zone has a serial");

        let applied = apply(&zone, &[add("new.example.com.", 3600, a("192.0.2.50"))]);
        let after = applied.zone.serial().expect("and so does the result");

        assert!(
            signed_serial(after, signed_at).is_newer_than(signed_serial(before, signed_at)),
            "an UPDATE inside one signing hour must still look like a new version"
        );

        // What a `max(file, now)` would have served instead: the same number
        // twice, because a date-style serial is larger than any current Unix
        // timestamp. Spelled out because "obviously right and silently does
        // nothing" is exactly how this design error survives review.
        //
        // The ten-digit `YYYYMMDDnn` form, which is the one the claim is about:
        // 2026080301 is 2.03e9 against an epoch of 1.75e9. The eight-digit
        // `YYYYMMDD` form is *smaller* than a current timestamp and the `max`
        // would swallow it whole rather than merely fail to move it — worse in
        // the same direction, and it is what this test asserted on the first
        // run, which is why the number is spelled with its `nn`.
        let date_style_before = Serial::new(2_026_080_301);
        let date_style_after = date_style_before.wrapping_add(1);
        let maxed = |file: Serial| Serial::new(file.to_u32().max(signed_at as u32));
        assert_eq!(
            maxed(date_style_before),
            Serial::new(date_style_before.to_u32()),
            "the max keeps the file's number for a date-style serial"
        );
        assert!(
            signed_serial(date_style_after, signed_at)
                .is_newer_than(signed_serial(date_style_before, signed_at)),
            "whereas the addition carries the +1 through"
        );
    }
}
