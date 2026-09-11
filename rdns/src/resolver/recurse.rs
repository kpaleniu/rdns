//! Walking down from the root: referrals, the CNAME chain, and the budgets that
//! stop both.
//!
//! The membership rule is "deciding who to ask next". Every ceiling a hostile
//! delegation could run up is here — CNAME hops, nested nameserver lookups
//! (`MAX_NESTED`), QNAME minimisation's count (RFC 9156 §2.3) and the query
//! budget — because they are one question asked in four places and a missing one
//! is an unbounded walk, not a wrong answer.
//!
//! Not here: whether the answer is *authentic*, which is [`super::validate`] and
//! runs over what this returns, and what to do with it, which is the parent's
//! `resolve`. The split is deliberate — checking signatures before the chain of
//! trust lets an attacker pick the key that validates their own data.

// The parent's `use` block, not a copy per file: these three are continuations
// of one `impl Resolver`, and a second import list is a second thing to drift.
use super::*;

/// What a referral told us.
struct Referral {
    zone: Name,
    ns_names: Vec<Name>,
    glue: Vec<SocketAddr>,
    /// Shortest TTL among the records the delegation rests on.
    ttl: u64,
}

impl Resolver {
    /// Resolve by walking the delegation chain, following any CNAME chain the
    /// answer leads through.
    pub(super) async fn recurse(
        &self,
        query: &QuerySection,
        state: &mut Resolution,
    ) -> ResolveResult<DnsMessage> {
        let mut qname = query.qname.clone();
        let mut answers = Vec::new();
        // Names we have already asked about — asking twice means a CNAME loop.
        let mut queried: HashSet<Name> = HashSet::new();
        // Names whose records we are willing to accept: the original question
        // plus every CNAME target we have followed to get here.
        let mut chain: HashSet<Name> = HashSet::from([qname.clone()]);
        let mut last = None;

        for hop in 0..=self.config.max_cname_hops {
            if !queried.insert(qname.clone()) {
                return Err(ResolveError::no_response(format!("CNAME loop at {qname}")));
            }
            if hop == self.config.max_cname_hops {
                return Err(ResolveError::no_response(format!(
                    "CNAME chain longer than {} hops",
                    self.config.max_cname_hops
                )));
            }

            let step = QuerySection {
                qname: qname.clone(),
                qtype: query.qtype,
                qclass: query.qclass,
            };
            let Answered { response, zone } = self.resolve_from_root(&step, state, 0).await?;

            // Only the last hop's authority section is returned, but a
            // wildcard-expanded CNAME earlier in the chain still owes its NSEC.
            if self.config.dnssec.is_some() {
                state.record_denials(&response.authorities);
            }

            // Keep only records on the chain asked about. Records volunteered
            // for unrelated names are cache-poisoning attempts, and `rdnsr`
            // caches whatever is returned here.
            for rr in &response.answers {
                // No copy per record any more: the set is keyed on the name
                // itself, whose `Hash` folds ASCII.
                let owner = rr.name.as_ref();
                if chain.contains(&rr.name) {
                    answers.push(rr.clone());
                    if rr.rdata.rtype() == rt::CNAME {
                        if let Ok(ParsedRecord::CNAME(target)) = rr.rdata.parse() {
                            chain.insert(target);
                        }
                    }
                    continue;
                }
                // A DNAME never owns the name asked about — it owns an
                // *ancestor* of it (RFC 6672 §2.2) — so the test above cannot
                // ever accept one, and dropping it loses the only signed half
                // of the redirection: "the CNAME will never be signed" (§5.3.1),
                // so a validating client that gets the CNAME without the DNAME
                // has nothing to check.
                //
                // Bailiwick is the whole of the guard. Without it a server for
                // `example.com.` answers with `com. DNAME evil.test.` and
                // redirects every name under `com.` in this cache.
                if rr.rdata.rtype() == rt::DNAME
                    && owner.is_at_or_under(zone.as_ref())
                    && chain
                        .iter()
                        .any(|n| n.as_ref() != owner && n.as_ref().is_at_or_under(owner))
                {
                    answers.push(rr.clone());
                }
            }

            // Done if we got the type we asked for, or if there is no CNAME to
            // follow (an empty answer is NODATA/NXDOMAIN, which is an answer).
            let got_type = response
                .answers
                .iter()
                .any(|rr| query.qtype.matches(rr.rdata.rtype()) && rr.name == qname);
            let cname = response
                .answers
                .iter()
                .filter(|rr| rr.rdata.rtype() == rt::CNAME && rr.name == qname)
                .find_map(|rr| match rr.rdata.parse() {
                    Ok(ParsedRecord::CNAME(target)) => Some(target),
                    _ => None,
                });

            // RFC 6672 §3.4: "Recursive caching name servers MUST perform
            // CNAME synthesis on behalf of clients." A conforming authoritative
            // server sends the CNAME itself (§3.1), but it is not obliged to be
            // conforming and a cache may hold the DNAME alone, so when no CNAME
            // arrived the substitution is ours to make.
            let next = match cname {
                Some(target) => Some(target),
                None if got_type || query.qtype.is(rt::CNAME) => None,
                None => {
                    synthesize_from_dname(&response, zone.as_ref(), qname.as_ref(), &mut answers)?
                }
            };
            if let Some(target) = &next {
                chain.insert(target.clone());
            }

            last = Some(response);
            if got_type || next.is_none() || query.qtype.is(rt::CNAME) {
                break;
            }
            qname = next.expect("checked is_none above");
        }

        let mut response = last
            .ok_or_else(|| ResolveError::no_response(format!("no response for {}", query.qname)))?;
        // Present the whole chain under the question the client actually asked.
        response.queries = vec![query.clone()];
        response.answers = answers;
        response.authoritive = false;
        Ok(response)
    }

    /// One name's worth of delegation walking: start at the root hints and
    /// follow referrals until a server answers authoritatively.
    ///
    /// `depth` counts *nested* resolutions — a nameserver address lookup
    /// re-enters here — capped separately so glueless chains cannot recurse
    /// without bound.
    pub(super) async fn resolve_from_root(
        &self,
        query: &QuerySection,
        state: &mut Resolution,
        depth: usize,
    ) -> ResolveResult<Answered> {
        const MAX_NESTED: usize = 4;
        if depth > MAX_NESTED {
            return Err(ResolveError::no_response(format!(
                "nameserver lookup nested deeper than {MAX_NESTED}"
            )));
        }

        // Start as far down the tree as already known. Validating narrows that:
        // a shortcut past a zone cut skips its DS records, so only zones whose
        // keys are already validated may be jumped to.
        if let Some((zone, servers)) = self.best_start(query.qname.as_ref()) {
            match self.walk(query, state, depth, zone.clone(), servers).await {
                Ok(response) => return Ok(response),
                Err(_) => {
                    // Cached delegations go stale; restart from the root rather
                    // than fail a query on our own bookkeeping.
                    self.delegations.forget(zone.as_ref());
                }
            }
        }

        self.walk(
            query,
            state,
            depth,
            Name::root(),
            self.config.root_hints.clone(),
        )
        .await
    }

    /// The deepest cached delegation we are willing to start from.
    fn best_start(&self, qname: NameRef<'_>) -> Option<(Name, Vec<SocketAddr>)> {
        if self.config.dnssec.is_some() {
            self.delegations
                .best_match_where(qname, |zone| self.keys.holds(zone))
        } else {
            self.delegations.best_match(qname)
        }
    }

    /// The delegation walk proper, from a known starting point.
    async fn walk(
        &self,
        query: &QuerySection,
        state: &mut Resolution,
        depth: usize,
        start_zone: Name,
        start_servers: Vec<SocketAddr>,
    ) -> ResolveResult<Answered> {
        let qname = query.qname.clone();
        let qname_labels = qname.as_ref().label_count();

        // The zone whose servers we are talking to; bailiwick is judged against
        // it. A server for `com.` may delegate `example.com.` but may not
        // answer for `example.org.`.
        let mut zone = start_zone;
        let mut servers = start_servers;

        // Labels of `qname` the next minimized query reveals: one below the
        // starting zone, deepening a label at a time.
        let mut sent_labels = zone.as_ref().label_count() + 1;

        // The budget is the real limit; this only bounds a pathological spin.
        // Minimization can add a probe per empty-non-terminal label, hence
        // `+ qname_labels`.
        let max_steps = self.config.max_delegations + qname_labels + 1;
        // Counted rather than derived from `sent_labels`: a referral can move
        // `zone` several labels at once, and MAX_MINIMISE_COUNT bounds round
        // trips spent minimizing.
        let mut minimized_probes = 0usize;
        for _ in 0..max_steps {
            let minimizing =
                self.config.qname_minimization && minimized_probes < MAX_MINIMISE_COUNT;
            let labels = if minimizing {
                sent_labels.min(qname_labels)
            } else {
                qname_labels
            };
            // A suffix of the wire form, so the minimized name borrows and
            // only the copy the question carries is paid for.
            let sname = qname.as_ref().suffix(labels);
            let is_final = sname == qname.as_ref();
            if !is_final {
                minimized_probes += 1;
            }

            // A zone cut answers the A probe with a referral, a plain in-zone
            // name with NODATA — telling the two apart without disclosing the
            // leaf.
            let step = QuerySection {
                qname: sname.to_owned(),
                qtype: if is_final {
                    query.qtype
                } else {
                    MINIMIZED_PROBE_TYPE
                },
                qclass: query.qclass,
            };
            let out = self.build_query(&step, false)?;

            let Some(response) = self.ask_any(&servers, &out, &mut state.budget).await else {
                return Err(ResolveError::no_response(format!(
                    "no server for {zone} answered while resolving {qname}"
                )));
            };

            // Bailiwick is judged against the full `qname` even when a shorter
            // name was asked.
            if let Some(Referral {
                zone: child_zone,
                ns_names,
                glue,
                ttl,
            }) = self.extract_referral(&response, zone.as_ref(), qname.as_ref())?
            {
                // The only pass where the parent's DS — or the NSEC proving
                // there is none — is in front of us.
                if self.config.dnssec.is_some() {
                    state.record_cut(child_zone.as_ref(), &response.authorities);
                }

                servers = if glue.is_empty() {
                    // Glueless: each named server costs a resolution of its own.
                    self.resolve_nameserver_addresses(&ns_names, state, depth + 1)
                        .await?
                } else {
                    glue
                };

                if servers.is_empty() {
                    return Err(ResolveError::no_response(format!(
                        "no reachable nameserver for {child_zone}"
                    )));
                }
                self.delegations
                    .insert(child_zone.as_ref(), servers.clone(), ttl);
                // A referral may jump more than one label at once.
                sent_labels = child_zone.as_ref().label_count() + 1;
                zone = child_zone;
                continue;
            }

            if is_final {
                // No answer, not authoritative and no referral is a lame
                // delegation: an empty NOERROR would read as a definitive "no
                // such record", so fail into SERVFAIL instead.
                if !response.answers.is_empty() || response.authoritive {
                    return Ok(Answered { response, zone });
                }
                return Err(ResolveError::no_response(format!(
                    "lame delegation: {zone} gave no answer and no usable referral for {qname}"
                )));
            }

            // No referral on an intermediate probe.
            if response.rcode == ResponseCode::NoSuchDomain {
                // The ancestor does not exist, so neither does the full name
                // (RFC 8020).
                return Ok(Answered { response, zone });
            }
            // The label exists in this zone but is not a cut; go one deeper.
            sent_labels = labels + 1;
        }

        Err(ResolveError::no_response(format!(
            "more than {} referrals while resolving {qname}",
            self.config.max_delegations
        )))
    }

    /// Try the servers fastest-known-first, returning the first usable response
    /// and folding each round trip (or failure) back into the RTT estimates.
    pub(super) async fn ask_any(
        &self,
        servers: &[SocketAddr],
        out: &OutgoingQuery,
        budget: &mut Budget,
    ) -> Option<DnsMessage> {
        for server in self.rtt.order(servers) {
            if budget.spend().is_err() {
                return None;
            }
            let started = std::time::Instant::now();
            if let Ok(response) = self.query_server(&server, out).await {
                self.rtt
                    .record(&server, started.elapsed().as_secs_f64() * 1000.0);
                return Some(response);
            }
            // A server that failed or timed out is charged the full timeout, so
            // the next query for this zone tries a different one ahead of it.
            self.rtt.record(&server, self.config.timeout_ms as f64);
        }
        None
    }

    /// Pull a delegation out of a referral response, enforcing bailiwick.
    ///
    /// Returns the delegated zone, the NS names, and whatever glue addresses
    /// were usable. `Ok(None)` means the response contained no delegation we are
    /// willing to follow.
    fn extract_referral(
        &self,
        response: &DnsMessage,
        zone: NameRef<'_>,
        qname: NameRef<'_>,
    ) -> ResolveResult<Option<Referral>> {
        // The NS records in the authority section name the child zone.
        let mut child_zone: Option<Name> = None;
        let mut ns_names = Vec::new();
        // How long the delegation may be cached: the shortest TTL among the
        // records it rests on.
        let mut ttl = u64::MAX;

        for rr in &response.authorities {
            if rr.rdata.rtype() != rt::NS {
                continue; // only NS records delegate
            }
            let owner = rr.name.as_ref();

            // Bailiwick, the rule that keeps a hostile server in its lane: a
            // referral must be *below* the zone we asked (otherwise `com.` could
            // hand us the servers for `bank.example.`) and must be *at or above*
            // the name we are chasing (otherwise it is not progress toward it).
            if !owner.is_at_or_under(zone) || owner == zone {
                continue;
            }
            if !qname.is_at_or_under(owner) {
                continue;
            }
            match &child_zone {
                None => child_zone = Some(owner.to_owned()),
                // A single referral names one zone; ignore any others.
                Some(z) if z.as_ref() != owner => continue,
                _ => {}
            }
            if let Ok(ParsedRecord::NS(target)) = rr.rdata.parse() {
                ns_names.push(target);
                ttl = ttl.min(rr.ttl.as_u64());
            }
        }

        let Some(child_zone) = child_zone else {
            return Ok(None);
        };

        // Glue is trusted only where the responder has standing: names under
        // the zone *it* serves, not the zone it delegates to. The root's `com.`
        // referral carries glue for `a.gtld-servers.net.`, which is under
        // neither `com.` nor resolvable without it.
        let mut glue = Vec::new();
        for rr in &response.additionals {
            let owner = rr.name.as_ref();
            if !ns_names.iter().any(|ns| ns.as_ref() == owner) {
                continue;
            }
            if !owner.is_at_or_under(zone) {
                continue;
            }
            let port = self.config.server_port;
            match rr.rdata.parse() {
                Ok(ParsedRecord::A(addr)) => {
                    glue.push(SocketAddr::new(IpAddr::V4(addr), port));
                    ttl = ttl.min(rr.ttl.as_u64());
                }
                Ok(ParsedRecord::AAAA(addr)) => {
                    glue.push(SocketAddr::new(IpAddr::V6(addr), port));
                    ttl = ttl.min(rr.ttl.as_u64());
                }
                _ => {}
            }
        }

        Ok(Some(Referral {
            zone: child_zone,
            ns_names,
            glue,
            ttl: if ttl == u64::MAX { 0 } else { ttl },
        }))
    }

    /// Resolve nameserver names to addresses, for delegations that came without
    /// usable glue. Stops at the first name that yields an address; each lookup
    /// is charged to the budget.
    ///
    /// A first, then AAAA only if A found nothing: a dual-stacked nameserver
    /// costs one query, and an IPv6-only glueless delegation still resolves.
    async fn resolve_nameserver_addresses(
        &self,
        ns_names: &[Name],
        state: &mut Resolution,
        depth: usize,
    ) -> ResolveResult<Vec<SocketAddr>> {
        const A: u16 = 1;
        const AAAA: u16 = 28;
        for name in ns_names {
            let mut addrs: Vec<SocketAddr> = Vec::new();
            for qtype in [Qtype::of(Rtype::new(A)), Qtype::of(Rtype::new(AAAA))] {
                let lookup = QuerySection {
                    qname: name.clone(),
                    qtype,
                    qclass: crate::QueryClass::IN,
                };
                // Boxed: this closes the resolution cycle, and an `async fn`
                // future may not contain itself by value.
                let Ok(answered) = Box::pin(self.resolve_from_root(&lookup, state, depth)).await
                else {
                    continue;
                };
                let response = answered.response;
                addrs.extend(
                    response
                        .answers
                        .iter()
                        .filter_map(|rr| match rr.rdata.parse() {
                            Ok(ParsedRecord::A(addr)) => {
                                Some(SocketAddr::new(IpAddr::V4(addr), self.config.server_port))
                            }
                            Ok(ParsedRecord::AAAA(addr)) => {
                                Some(SocketAddr::new(IpAddr::V6(addr), self.config.server_port))
                            }
                            _ => None,
                        }),
                );
                if !addrs.is_empty() {
                    break;
                }
            }
            if !addrs.is_empty() {
                return Ok(addrs);
            }
        }
        Ok(Vec::new())
    }

    async fn query_server(
        &self,
        upstream: &SocketAddr,
        out: &OutgoingQuery,
    ) -> ResolveResult<DnsMessage> {
        // tokio's UdpSocket has no read timeout of its own.
        let read_timeout = Duration::from_millis(self.config.timeout_ms / 2);
        let socket = UdpSocket::bind(bind_addr_for(*upstream)).await?;
        socket.connect(upstream).await?;

        socket.send(&out.buf).await?;

        // Sized to the payload advertised via EDNS.
        let mut response_buf = vec![0; self.config.udp_payload_size as usize];
        let n = tokio::time::timeout(read_timeout, socket.recv(&mut response_buf)).await??;

        response_buf.truncate(n);
        let response = DnsMessage::try_from_bytes(&response_buf)?;

        // The connected socket filters by source address; the id and the echoed
        // (0x20-cased) name are the entropy an off-path spoofer must also match.
        if !self.response_matches(&response, out) {
            return Err(ResolveError::no_response(format!(
                "reply from {upstream} did not match the query"
            )));
        }

        // RFC 1035 §4.2.1: retry a truncated answer over TCP, on the *same*
        // upstream — TC is about the datagram, not the server's health.
        if response.truncation {
            return self.query_upstream_tcp(upstream, out).await;
        }

        Ok(response)
    }

    /// Re-issue a query over TCP, length-prefixed (RFC 1035 §4.2.2).
    ///
    /// A still-truncated response is returned as-is: TCP is the last resort, so
    /// the partial answer plus TC beats a hard failure.
    async fn query_upstream_tcp(
        &self,
        upstream: &SocketAddr,
        out: &OutgoingQuery,
    ) -> ResolveResult<DnsMessage> {
        if out.buf.len() > TCP_MAX_MESSAGE {
            return Err(ResolveError::no_response(format!(
                "query of {} bytes exceeds the 2-byte TCP length prefix",
                out.buf.len()
            )));
        }

        // Applied to each of connect, write and read.
        let timeout = Duration::from_millis(self.config.timeout_ms / 2);
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(upstream)).await??;

        // One write so prefix and message share a segment. The length is checked
        // rather than cast: a wrapped prefix reads as a broken stream.
        let framed = crate::framed(&out.buf)?;
        tokio::time::timeout(timeout, stream.write_all(&framed)).await??;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await??;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Err(ResolveError::no_response(format!(
                "upstream {} sent a zero-length TCP message",
                upstream
            )));
        }

        let mut response_buf = vec![0; len];
        tokio::time::timeout(timeout, stream.read_exact(&mut response_buf)).await??;
        let response = DnsMessage::try_from_bytes(&response_buf)?;

        // TCP is not off-path spoofable, but a mismatched id or question still
        // means a confused peer, not an answer to trust.
        if !self.response_matches(&response, out) {
            return Err(ResolveError::no_response(format!(
                "TCP reply from {upstream} did not match the query"
            )));
        }
        Ok(response)
    }
}

/// RFC 6672 §3.4.1 step 4D: apply a DNAME in the response to the name being
/// sought, and synthesize the CNAME the server did not send.
///
/// Called only when no CNAME arrived for `qname`. A conforming authoritative
/// server sends one (§3.1) and this does nothing; §3.4 makes the synthesis a
/// recursive server's obligation anyway, because a cache may hold the DNAME
/// alone.
///
/// The first applicable DNAME is the only one: "there will be at most one
/// ancestor with a DNAME as described in step 4 unless some zone's data is in
/// violation of the no-descendants limitation" (§3.2).
///
/// `Err` for an overflow, which is step 4D's "return an implementation-
/// dependent error to the application" — the authoritative server's YXDOMAIN
/// (§2.2) has no resolver-side spelling, and answering NOERROR with a partial
/// chain would say the name resolved to nothing rather than that it could not
/// be built.
fn synthesize_from_dname(
    response: &DnsMessage,
    zone: NameRef<'_>,
    qname: NameRef<'_>,
    answers: &mut Vec<ResourceRecord>,
) -> ResolveResult<Option<Name>> {
    for rr in &response.answers {
        if rr.rdata.rtype() != rt::DNAME || !rr.name.as_ref().is_at_or_under(zone) {
            continue;
        }
        let Ok(ParsedRecord::DNAME(target)) = rr.rdata.parse() else {
            continue;
        };
        match dname_redirect(qname, rr.name.as_ref(), target.as_ref()) {
            Redirect::NoMatch => continue,
            Redirect::TooLong => {
                return Err(ResolveError::no_response(format!(
                    "substituting {target} for {} in {qname} overflows 255 octets \
                     (RFC 6672 §3.4.1 step 4D)",
                    rr.name
                )))
            }
            Redirect::To(next) => {
                // "A CNAME RR with Time to Live (TTL) equal to the
                // corresponding DNAME RR is synthesized" (§3.1) — and for a
                // cache, "equal to the decremented TTL of the cached DNAME",
                // which is what arrived on the wire.
                let rdata = RecordData::from_parsed(&ParsedRecord::CNAME(next.clone()))
                    .map_err(|e| ResolveError::no_response(format!("synthesizing a CNAME: {e}")))?;
                answers.push(ResourceRecord {
                    name: qname.to_owned(),
                    class: rr.class,
                    ttl: rr.ttl,
                    rdata,
                });
                return Ok(Some(next));
            }
        }
    }
    Ok(None)
}
