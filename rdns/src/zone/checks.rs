//! Zone-wide rules that must be refused at load, because at query time there is
//! no correct answer to give.
//!
//! The membership rule is exactly that: a check belongs here when the only honest
//! reply to a query against the broken zone would be a wrong one. A CNAME sharing
//! its name with another type (RFC 1034 §3.6.2), and RFC 6672's three DNAME cases
//! — the singleton rule and data below a DNAME (§2.4), and a wildcard DNAME
//! (§3.3) — are all of that kind: a name with two answers and no rule for
//! choosing between them.
//!
//! Two boundaries, and both are load-bearing:
//!
//! - **Not per-record validity.** Whether one record's RDATA is well formed
//!   belongs to [`crate::RecordData`], which seals its fields against exactly
//!   that. These are relations *between* records, so they cannot be asked until
//!   the whole zone is in memory.
//! - **Not an invariant the answer path may rely on.** A zone that arrives by
//!   transfer or grows by dynamic update never passes through here, and RFC 6672
//!   §5.2 has UPDATE adding a DNAME over existing names on purpose. Refusing at
//!   load is an operator's error message, not a guarantee; [`super::Zone`] still
//!   has to answer correctly for a zone that never met these.
//!
//! All-or-nothing is the caller's rule and `CLAUDE.md` §4's: a zone that fails one
//! of these is not served at all, because one typo plus a reload is otherwise a
//! lame delegation with every dashboard green.

use super::Zone;
use crate::error::ZoneError;
use crate::record_types as rt;
use crate::{NameRef, Rtype};

/// RFC 1034 §3.6.2: a CNAME must be the only type at its owner name. Refused at
/// load, because there is no correct answer to give at query time.
///
/// RRSIG, NSEC and NSEC3 are excepted — they describe the name rather than name
/// it (RFC 4035 §2.5).
///
/// Asked of `Zone::groups`, the owner-name grouping the index already is: a
/// second `HashMap<Name, _>` built here cost a `Name` clone and a `Vec` per
/// record and was a third of a million-rule RPZ load (`CLAUDE.md` §13, "a scan
/// beside the index that would have answered it").
pub(super) fn check_cname_exclusivity(zone: &Zone) -> Result<(), ZoneError> {
    for positions in zone.groups() {
        // One record cannot be a CNAME *and* another type, and an empty
        // non-terminal has none.
        if positions.len() < 2 {
            continue;
        }
        let mut has_cname = false;
        let mut others: Vec<Rtype> = Vec::new();
        for &position in positions {
            let rtype = zone.record(position).rdata.rtype();
            if matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3) {
                continue;
            }
            if rtype == rt::CNAME {
                has_cname = true;
            } else if !others.contains(&rtype) {
                others.push(rtype);
            }
        }
        if has_cname && !others.is_empty() {
            let name = zone.record(positions[0]).name;
            let others: Vec<String> = others.iter().map(Rtype::to_string).collect();
            return Err(ZoneError::invalid(format!(
                "{name} has a CNAME and also type(s) {} — RFC 1034 §3.6.2 allows a CNAME to be \
                 the only type at a name, and a resolver given both has no way to know which \
                 answer it was meant to get",
                others.join(", ")
            )));
        }
    }
    Ok(())
}

/// What RFC 6672 says a zone holding a DNAME may not do. Refused at load, for
/// the reason [`check_cname_exclusivity`] is: each of these is a name with two
/// answers and no rule for choosing between them.
///
/// The RFC hedges — "ought to refuse" for the singleton rule (§2.4), "MAY
/// refuse" for data below a DNAME (§2.4) and for a wildcard DNAME (§3.3). All
/// three are refused here, because the alternative is a zone that loads and
/// then cannot serve what it holds: a name below a DNAME is occluded
/// (RFC 2136 §7.18) whatever the file says.
///
/// This is the *loader's* check, so a zone that arrives by transfer or is built
/// by dynamic update never meets it — §5.2 has dynamic update adding a DNAME
/// over existing names on purpose. That is why the answer path occludes rather
/// than trusting this: [`Zone::dname_above`] decides the answer for any zone,
/// however it got here.
pub(super) fn check_dname_rules(zone: &Zone) -> Result<(), ZoneError> {
    let apex = zone.origin();
    let mut owners: Vec<NameRef<'_>> = Vec::new();

    for record in zone.records() {
        if record.rdata.rtype() != rt::DNAME {
            continue;
        }
        let key = record.name;
        // Only for the message: comparisons below are the name's own.
        let shown = key.to_presentation();

        // §3.3: "records of the form `*.example.com DNAME example.net` SHOULD
        // NOT be used", because "the interaction between the expansion of the
        // wildcard and the redirection of the DNAME is non-deterministic".
        // Non-deterministic is not a thing a server can be asked to serve.
        if key.labels().next() == Some(b"*") {
            return Err(ZoneError::invalid(format!(
                "{shown} is a wildcard DNAME — RFC 6672 §3.3 says the interaction between \
                 wildcard expansion and DNAME redirection is non-deterministic, so there is \
                 no one answer for a server to give"
            )));
        }

        // §2.4: "The owner name of a DNAME can only have one DNAME RR, and no
        // CNAME RRs can exist at that name." Only the first half is here: a
        // CNAME sharing its owner with anything at all is already refused by
        // `check_cname_exclusivity` citing RFC 1034 §3.6.2, the older statement
        // of the same rule. A second check would be a second message for one
        // condition, and the two would drift (`CLAUDE.md` §7).
        if owners.contains(&key) {
            return Err(ZoneError::invalid(format!(
                "{shown} has two DNAME records — RFC 6672 §2.4 makes DNAME a singleton type, \
                 so that one name has one redirection and nothing has to choose between them"
            )));
        }

        // §2.3: "DNAME RRs MUST NOT appear at the same owner name as an NS RR
        // unless the owner name is the zone apex; if it is not the zone apex,
        // then the NS RR signifies a delegation point, and the DNAME RR must in
        // that case appear below the zone cut at the zone apex of the child
        // zone."
        if key != apex && zone.has_type(key, rt::NS) {
            return Err(ZoneError::invalid(format!(
                "{shown} has both a DNAME and an NS RRset below the apex — RFC 6672 §2.3 \
                 forbids it, because the NS makes this a zone cut and the DNAME then belongs \
                 in the child zone"
            )));
        }

        owners.push(key);
    }

    if owners.is_empty() {
        return Ok(());
    }

    // §2.4: "Resource records MUST NOT exist at any subdomain of the owner of a
    // DNAME RR."
    //
    // The denial types are exempt. They describe the zone's shape rather than
    // being names it answers for, and a DNAME at the apex — which §2.3 allows
    // outright, SOA and NS beside it — puts every NSEC3 record in the zone
    // below a DNAME owner, so counting them would refuse a zone the RFC spells
    // out as legal.
    for record in zone.records() {
        let rtype = record.rdata.rtype();
        if matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3 | rt::NSEC3PARAM) {
            continue;
        }
        let key = record.name;
        for &owner in &owners {
            if key != owner && key.is_at_or_under(owner) {
                let (key, owner) = (key.to_presentation(), owner.to_presentation());
                return Err(ZoneError::invalid(format!(
                    "{key} is below the DNAME at {owner} — RFC 6672 §2.4 says resource \
                     records must not exist at any subdomain of a DNAME owner, and this one \
                     could never be answered with: the redirection is applied before the name \
                     is looked up"
                )));
            }
        }
    }
    Ok(())
}
