use super::Zone;
use crate::error::ZoneError;
use crate::utils::record_type_code;
use crate::utils::record_types as rt;
use crate::{Name, Rtype};
use std::collections::HashMap;

/// RFC 1034 §3.6.2: a CNAME must be the only type at its owner name. Refused at
/// load, because there is no correct answer to give at query time.
///
/// RRSIG, NSEC and NSEC3 are excepted — they describe the name rather than name
/// it (RFC 4035 §2.5).
pub(super) fn check_cname_exclusivity(zone: &Zone) -> Result<(), ZoneError> {
    let mut by_name: HashMap<Name, (bool, Vec<Rtype>)> = HashMap::new();
    for record in zone.records() {
        let rtype = record_type_code(&record.rdata);
        if matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3) {
            continue;
        }
        let entry = by_name
            .entry(record.name.clone())
            .or_insert((false, Vec::new()));
        if rtype == rt::CNAME {
            entry.0 = true;
        }
        if !entry.1.contains(&rtype) {
            entry.1.push(rtype);
        }
    }

    for (name, (has_cname, types)) in by_name {
        if has_cname && types.len() > 1 {
            let others: Vec<String> = types
                .iter()
                .filter(|&&t| t != rt::CNAME)
                .map(|t| t.to_string())
                .collect();
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
    let mut owners: Vec<&Name> = Vec::new();

    for record in zone.records() {
        if record_type_code(&record.rdata) != rt::DNAME {
            continue;
        }
        let key = &record.name;
        // Only for the message: comparisons below are the name's own.
        let shown = key.as_ref().to_presentation();

        // §3.3: "records of the form `*.example.com DNAME example.net` SHOULD
        // NOT be used", because "the interaction between the expansion of the
        // wildcard and the redirection of the DNAME is non-deterministic".
        // Non-deterministic is not a thing a server can be asked to serve.
        if key.as_ref().labels().next() == Some(b"*") {
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
        if key.as_ref() != apex && zone.has_type(key.as_ref(), rt::NS) {
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
        let rtype = record_type_code(&record.rdata);
        if matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3 | rt::NSEC3PARAM) {
            continue;
        }
        let key = record.name.as_ref();
        for owner in &owners {
            if key != owner.as_ref() && key.is_at_or_under(owner.as_ref()) {
                let (key, owner) = (key.to_presentation(), owner.as_ref().to_presentation());
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
