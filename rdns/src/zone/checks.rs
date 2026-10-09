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
/// RRSIG, NSEC and NSEC3 are excepted (RFC 4035 §2.5). Asked of `Zone::groups`,
/// the grouping the index already is (`CLAUDE.md` §13).
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

/// What RFC 6672 says a zone holding a DNAME may not do, each a name with two
/// answers and no rule to choose: refused at load, all three hedged rules
/// (§2.4, §3.3). A transfer or UPDATE never meets this check, so the answer
/// path occludes too ([`Zone::dname_above`]).
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

        // §3.3: a wildcard DNAME's interaction "is non-deterministic", which a
        // server cannot serve.
        if key.labels().next() == Some(b"*") {
            return Err(ZoneError::invalid(format!(
                "{shown} is a wildcard DNAME — RFC 6672 §3.3 says the interaction between \
                 wildcard expansion and DNAME redirection is non-deterministic, so there is \
                 no one answer for a server to give"
            )));
        }

        // §2.4's one DNAME per owner; the no-CNAME half is
        // `check_cname_exclusivity`'s (`CLAUDE.md` §7).
        if owners.contains(&key) {
            return Err(ZoneError::invalid(format!(
                "{shown} has two DNAME records — RFC 6672 §2.4 makes DNAME a singleton type, \
                 so that one name has one redirection and nothing has to choose between them"
            )));
        }

        // §2.3: a DNAME beside NS only at the apex; elsewhere NS is a
        // delegation, and the DNAME belongs in the child.
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

    // §2.4: nothing below a DNAME owner. Denial types are exempt: an apex
    // DNAME, which §2.3 allows, puts every NSEC3 below it.
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
