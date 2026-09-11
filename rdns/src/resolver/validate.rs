//! How much of a response is authentic: one function, and the order it works in.
//!
//! The chain of trust first, the signatures second. That order is the whole
//! reason this is its own module rather than a step inside [`super::recurse`]:
//! validating a signature and *then* asking where its key came from lets the
//! sender choose the key that validates their own data.
//!
//! The DNSSEC machinery itself — the chain walk, the denial proofs, the
//! algorithms — is [`crate::dnssec_chain`] and its neighbours. What is here is
//! only the resolver's use of it: which of a response's sections may be believed,
//! and the AD bit that follows.

// The parent's `use` block, not a copy per file: these three are continuations
// of one `impl Resolver`, and a second import list is a second thing to drift.
use super::*;

impl Resolver {
    /// Decide how much of `response` is authentic.
    ///
    /// Chain of trust first, signatures second. Checking signatures first and
    /// chasing the chain only if they pass lets an attacker choose the key that
    /// validates their own data.
    pub(super) async fn validate(
        &self,
        query: &QuerySection,
        response: &DnsMessage,
        state: &mut Resolution,
        anchors: &TrustAnchors,
    ) -> ValidationState {
        let now = current_unix_timestamp();

        // "Negative" is not `answers.is_empty()`: a CNAME chain ending without
        // the queried type is a negative answer with a non-empty answer section.
        // RFC 4035 §5.4 keys the proof to the name actually denied, which after a
        // chain is the end of the chain, not the name asked about.
        let shape = cname_chain_shape(query.qname.as_ref(), query.qtype, &response.answers);
        let denied_name = match &shape {
            ChainShape::Intact { final_name } => final_name.clone(),
            // Judged after the signatures, so an unsigned zone still reads
            // Insecure rather than Bogus.
            ChainShape::Broken(_) => query.qname.clone(),
        };
        let holds_the_answer = response
            .answers
            .iter()
            .any(|rr| query.qtype.matches(rr.rdata.rtype()) && rr.name == denied_name);
        let negative = !holds_the_answer;

        // Both sections: the proof is in the authority section, but a
        // CNAME-terminated "no" also hands the client real records.
        let mut records: Vec<ResourceRecord> = response.answers.clone();
        if negative {
            records.extend(response.authorities.iter().cloned());
        }

        // Every zone that put its name to something here.
        let mut signers: Vec<Name> = Vec::new();
        for sig in records.iter().filter_map(Rrsig::from_record) {
            let signer = sig.signer_name;
            if !signers.contains(&signer) {
                signers.push(signer);
            }
        }

        // Nothing signed is either an unsigned zone or a signed one stripped in
        // flight; only the chain walk tells the two apart.
        if signers.is_empty() {
            let mut keys = KeyStore::new();
            return match self
                .establish_chain(query.qname.as_ref(), state, anchors, now, &mut keys)
                .await
            {
                ValidationState::Secure => ValidationState::Bogus(format!(
                    "{} lies in a signed zone but nothing in the answer is signed",
                    query.qname
                )),
                other => other,
            };
        }

        let mut keys = KeyStore::new();
        for signer in &signers {
            match self
                .establish_chain(signer.as_ref(), state, anchors, now, &mut keys)
                .await
            {
                ValidationState::Secure => {}
                // The chain ends in an unsigned zone, so the signature means
                // nothing and cannot be held against it either.
                other => return other,
            }
        }

        let validator = ChainValidator::new(anchors, now);
        let verdict = validator.validate_records(&records, &keys);
        if !verdict.state.is_secure() {
            return verdict.state;
        }

        // A signature over a denial says the records are authentic, not that
        // they deny what was asked; without this check a valid NSEC from
        // elsewhere in the zone stands in for a proof it does not make.
        if negative {
            // A chain that is not a chain must not be laundered into a denial:
            // its "final name" is not one we asked about.
            if let ChainShape::Broken(why) = shape {
                return ValidationState::Bogus(why);
            }
            return self.check_denial(query, denied_name.as_ref(), response);
        }

        // Shape, independently of signatures: a genuine CNAME beside a genuine A
        // for an unrelated name is two valid RRsets and no chain. Checked here
        // rather than in `recurse`'s per-hop filter so it also covers an answer
        // that arrived whole from a forwarder.
        if let ChainShape::Broken(why) = shape {
            return ValidationState::Bogus(why);
        }

        // A wildcard's signature verifies at every name it could expand to, so a
        // verified answer is not yet an answer *about* the name asked. The denial
        // that makes it one may have arrived on an earlier hop of a CNAME chase.
        if !verdict.wildcards.is_empty() {
            let mut proofs = response.authorities.clone();
            proofs.extend(state.denials.iter().cloned());
            return validator.validate_wildcard_proofs(&verdict.wildcards, &proofs, &keys);
        }
        ValidationState::Secure
    }

    /// Walk from a trust anchor down to `target`, filling `keys` with the
    /// validated DNSKEY set of every zone on the way.
    ///
    /// Returns [`ValidationState::Secure`] when `target`'s own zone was
    /// reached and is signed, `Insecure` when the chain provably ends above it,
    /// and `Bogus` when it breaks.
    async fn establish_chain(
        &self,
        target: NameRef<'_>,
        state: &mut Resolution,
        anchors: &TrustAnchors,
        now: u64,
        keys: &mut KeyStore,
    ) -> ValidationState {
        let validator = ChainValidator::new(anchors, now);
        let Some((anchor_zone, anchor_ds)) = validator.start(target) else {
            return ValidationState::Indeterminate(format!("no trust anchor covers {target}"));
        };

        // Resume as deep as already trusted, by the same rule `best_start` used
        // to pick where the resolution began. Disagreeing makes the walk skip a
        // zone cut whose DS this loop then goes looking for.
        let (mut zone, mut ds_set) = (anchor_zone.clone(), anchor_ds);
        for candidate in target.ancestors() {
            if candidate.is_at_or_under(anchor_zone.as_ref()) && self.keys.holds(candidate) {
                // Cached keys were validated to the anchor already, so the DS
                // that got us there is not needed again.
                zone = candidate.to_owned();
                ds_set = Vec::new();
                break;
            }
        }

        // A chain is at most one zone cut per label, plus the anchor.
        let max_steps = target.label_count() + 2;
        for _ in 0..max_steps {
            let zone_keys = match self.keys.get(zone.as_ref()) {
                Some(cached) => cached,
                None => {
                    let (records, ttl) = match self.fetch_dnskeys(zone.as_ref(), state).await {
                        Ok(found) => found,
                        Err(e) => {
                            return ValidationState::Bogus(format!(
                                "could not fetch the DNSKEY RRset for {zone}: {e:#}"
                            ))
                        }
                    };
                    match validator.validate_dnskeys(zone.as_ref(), &records, &ds_set) {
                        Ok(validated) => {
                            self.keys.insert(zone.as_ref(), validated.clone(), ttl);
                            validated
                        }
                        Err(other) => return other,
                    }
                }
            };
            keys.insert(zone.as_ref().to_folded(), zone_keys.clone());

            if zone.as_ref() == target {
                return ValidationState::Secure;
            }

            let Some(evidence) = state.next_cut_below(zone.as_ref(), target).cloned() else {
                // No cut below: the target is served out of this zone, so these
                // keys are the ones that signed it.
                return ValidationState::Secure;
            };

            match validator.validate_delegation(&evidence, zone.as_ref(), &zone_keys) {
                DelegationVerdict::Secure(ds) => {
                    ds_set = ds;
                    zone = evidence.zone.clone();
                }
                DelegationVerdict::Insecure(_) => return ValidationState::Insecure,
                DelegationVerdict::Bogus(why) => return ValidationState::Bogus(why),
            }
        }

        ValidationState::Bogus(format!("the chain of trust to {target} does not terminate"))
    }

    /// Fetch a zone's DNSKEY RRset, returning the records and the TTL to cache
    /// the conclusion for.
    async fn fetch_dnskeys(
        &self,
        zone: NameRef<'_>,
        state: &mut Resolution,
    ) -> Result<(Vec<ResourceRecord>, u64), ResolveError> {
        let query = QuerySection {
            qname: zone.to_owned(),
            qtype: Qtype::of(rt::DNSKEY),
            qclass: crate::QueryClass::IN,
        };
        let response = match self.config.mode {
            ResolverMode::Forward => Box::pin(self.forward(&query, state)).await?,
            ResolverMode::Recurse => {
                Box::pin(self.resolve_from_root(&query, state, 0))
                    .await?
                    .response
            }
        };
        let ttl = response
            .answers
            .iter()
            .filter(|rr| rr.rdata.rtype() == rt::DNSKEY)
            .map(|rr| rr.ttl.as_u64())
            .min()
            .unwrap_or(0);
        Ok((response.answers, ttl))
    }

    /// Check that the NSEC/NSEC3 records deny what was asked, not merely that
    /// they are correctly signed. `denied_name` is the end of the CNAME chain,
    /// not the name asked about (RFC 4035 §5.4).
    fn check_denial(
        &self,
        query: &QuerySection,
        denied_name: NameRef<'_>,
        response: &DnsMessage,
    ) -> ValidationState {
        let nsecs = nsecs_in(&response.authorities);
        let nsec3s = nsec3s_in(&response.authorities);
        if nsecs.is_empty() && nsec3s.is_empty() {
            // A signed zone answering "no" without proof; common from a
            // middlebox, but not something to pass on as authenticated.
            return ValidationState::Bogus(format!(
                "{denied_name} was denied without an NSEC or NSEC3 proof"
            ));
        }

        // The zone the proof came from — the SOA in the authority section names
        // it, and failing that the shallowest NSEC owner we were given.
        let zone = response
            .authorities
            .iter()
            .find(|rr| rr.rdata.rtype() == rt::SOA)
            .map(|rr| rr.name.clone())
            .unwrap_or_else(|| denied_name.to_owned());

        let denial = if response.rcode == ResponseCode::NoSuchDomain {
            proves_nxdomain(denied_name, zone.as_ref(), &nsecs, &nsec3s)
        } else {
            proves_nodata(
                denied_name,
                zone.as_ref(),
                Rtype::new(query.qtype.to_u16()),
                &nsecs,
                &nsec3s,
            )
        };

        match denial {
            Denial::Proved => ValidationState::Secure,
            Denial::NotProved(why) => ValidationState::Bogus(format!(
                "the denial of {denied_name} does not prove it: {why}"
            )),
        }
    }
}
