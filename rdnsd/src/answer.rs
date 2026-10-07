//! Turning a message into a response: everything about the request rather than
//! the zone.
//!
//! The opcode, EDNS, the class, AXFR and IXFR over UDP, which zone is asked
//! (`Zones::for_query`), and REFUSED when none is. What one zone then says to
//! the question — RFC 1034 §4.3.2's four cases and the DNSSEC records each owes
//! — is [`rdns::zone_answer`]'s (`TODO.md` #150).
//!
//! Everything here is a synchronous function of the message, the zone map and
//! the metrics — no sockets, no lock guards, nothing `async`.
//!
//! The answer is written to the wire as it is found, through a
//! [`ResponseWriter`], rather than built as a `DnsMessage` and serialized
//! afterwards: an owner `String`, a cloned RDATA and a `Vec` push per record
//! were three of the twelve allocations a query cost (`TODO.md` #27b).

use rdns::ede::InfoCode;
use rdns::error::WireError;
use rdns::metrics::{DnsMetrics, LatencyTimer};
use rdns::record_types;
use rdns::response::{ResponseWriter, Section, ServerOpt};
use rdns::Qtype;
use rdns::{DnsMessage, Edns, ExtendedError, OpCode, QueryClass, ResponseCode};
#[cfg(test)]
use rdns::{ParsedRecord, RecordData};

use crate::zones::Zones;
use crate::Scratch;

/// Write a DNS response to `msg` into `scratch.out`, at most `max_len` octets,
/// advertising `advertised` in the OPT it mirrors back.
///
/// `scratch` is the caller's to keep: a worker answering one datagram after
/// another reuses it and the answer costs the allocator nothing. Over `max_len`
/// the reply is an empty TC=1 one (RFC 1035 §4.2.1).
pub(crate) fn write_response(
    msg: &DnsMessage,
    zones: &Zones,
    metrics: &DnsMetrics,
    max_len: usize,
    advertised: ServerOpt,
    scratch: &mut Scratch,
) -> Result<(), WireError> {
    let timer = LatencyTimer::new();
    let Scratch { out, compressor } = scratch;
    let mut w = ResponseWriter::start(out, compressor, max_len, msg)?;
    w.set_authoritative(true);

    // EDNS-level rejections take precedence over any zone lookup: a malformed
    // option list is FORMERR, an EDNS version we don't implement is BADVERS.
    // Both replies carry a bare version-0 OPT — BADVERS is an extended RCODE, so
    // the OPT record is what carries its high bits. `rdnsr` reads the same
    // decision out of `client_edns` (`TODO.md` #30h).
    let client_edns = match rdns::response::client_edns(msg) {
        Ok(edns) => edns,
        Err(rcode) => {
            w.set_rcode(rcode);
            // `with_payload_size` carries no options, so encoding it cannot fail.
            w.set_edns(Edns::with_payload_size(advertised.payload_size));
            return w.finish();
        }
    };

    // DO says the client can make sense of DNSSEC records, so send them
    // (RFC 4035 §3.1.1). Not a demand that the zone be signed.
    let dnssec_ok = client_edns.do_bit();

    // Only QUERY reaches the zone lookup. NOTIFY is answered by the caller,
    // which knows the peer's address; anything else is NOTIMP rather than
    // treated as a lookup (RFC 1035 §4.1.1).
    if msg.opcode != OpCode::Query {
        w.set_rcode(ResponseCode::NotImplemented);
        w.set_authoritative(false);
        w.set_extended_error(UNIMPLEMENTED_OPCODE);
        // This `return` jumps over the EDNS mirroring at the end of the
        // function, and RFC 6891 §6.1.1 says a response to a request that had an
        // OPT includes one. Some clients remember a missing OPT as a downgrade
        // and never offer EDNS again.
        //
        // `ClientEdns::Present` and `msg.has_edns()` agree here: they differ
        // only for a malformed option list, which answered FORMERR above.
        if let Some(edns) = client_edns.mirror(advertised) {
            w.set_edns(edns);
        }
        return w.finish();
    }

    // Exactly one question, or FORMERR. RFC 9619 §4: "A DNS message with
    // OPCODE = 0 MUST NOT include a QDCOUNT parameter whose value is greater
    // than 1", and one that does "MUST be treated as an incorrectly formatted
    // message" — one RCODE, one AA bit and one set of sections cannot describe
    // two lookups.
    //
    // QDCOUNT = 0 was NOERROR here until `TODO.md` #78c, on the strength of
    // §4's other sentence — which binds *firewalls* ("Such firewalls MUST NOT
    // treat messages with OPCODE = 0 and QDCOUNT = 0 as malformed"), not
    // responders, and left AA set over a question section naming nothing to be
    // authoritative for. RFC 7873 §5.4 is what such a query is for and extends
    // the QUERY opcode to it only "for servers with DNS Cookies enabled";
    // without cookies it says such a server "will normally send FORMERR".
    // Measured: BIND 9.20.27, Knot 3.6.0, NSD 4.12.0 and Unbound 1.23.1 all
    // answer FORMERR to one carrying no OPT, and none of them sets AA.
    match msg.queries.as_slice() {
        [query] => answer_question(query, zones, dnssec_ok, &mut w)?,
        _ => {
            w.set_rcode(ResponseCode::FormatError);
            w.set_authoritative(false);
        }
    }

    // Count the answer by what it says. REFUSED climbing means a zone went
    // missing, SERVFAIL that one went wrong, NXDOMAIN is ordinary.
    metrics.count_response(w.rcode());
    if w.is_authoritative() {
        metrics.count(&metrics.queries_authoritative);
    }
    metrics.observe_latency_us(timer.elapsed_us());

    // Mirror EDNS0: an OPT record only when the client used EDNS
    // (RFC 6891 §6.1.1), and DO echoed when it was asked for (RFC 3225 §3).
    if let Some(edns) = client_edns.mirror(advertised) {
        w.set_edns(edns);
    }

    w.finish()
}

/// Why a NOTIMP is NOTIMP (RFC 8914 §4.22): "the requested operation or query
/// is not supported". Which operation is the client's own opcode, so the text
/// says only which of this server's two NOT_SUPPORTED sites it came from.
const UNIMPLEMENTED_OPCODE: ExtendedError =
    ExtendedError::new(InfoCode::NOT_SUPPORTED, "this opcode is not implemented");

/// NOT_SUPPORTED rather than [`NOT_OUR_ZONE`], though the two arrive at the
/// same REFUSED: what is absent is the class, not the zone, and the operator's
/// fix differs. Serving CH at all is `docs/adr/0003`.
const UNSERVED_CLASS: ExtendedError =
    ExtendedError::new(InfoCode::NOT_SUPPORTED, "this class is not served");

/// Why a REFUSED for a name we hold no zone for is REFUSED (RFC 8914 §4.21).
///
/// One constant because the two sites are one decision seen twice — the ordinary
/// lookup and the IXFR-over-UDP shortcut both fall through to `for_query`
/// finding nothing — and a second spelling is where the two would drift
/// (`CLAUDE.md` §7).
pub(crate) const NOT_OUR_ZONE: ExtendedError = ExtendedError::new(
    InfoCode::NOT_AUTHORITATIVE,
    "no zone here is at or above this name",
);

/// The one question, once the message-level answers are out of the way.
fn answer_question(
    query: &rdns::QuerySection,
    zones: &Zones,
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    // Every zone here is IN, and RFC 1034 §4.3.2 step 1 searches the zones
    // *of the question's class* — so a CH or HS question is the same
    // situation as a zone we do not serve, and REFUSED for the reason at the
    // bottom of this function. QCLASS=ANY (255) matches any class
    // (RFC 1035 §3.2.5), so it is not refused.
    if !matches!(query.qclass, QueryClass::IN | QueryClass::Any) {
        w.set_rcode(ResponseCode::Refused);
        w.set_authoritative(false);
        w.set_extended_error(UNSERVED_CLASS);
        return Ok(());
    }

    // AXFR is defined over TCP alone (RFC 5936 §4.2), so a UDP request for
    // it is malformed rather than merely refused. The TCP server answers
    // AXFR before reaching here, so this is the UDP path speaking.
    if query.qtype == Qtype::AXFR {
        w.set_rcode(ResponseCode::FormatError);
        return Ok(());
    }

    // An IXFR over UDP is expected. RFC 1995 §2: answer a single SOA of the
    // current version, telling the client to come back over TCP. Done
    // always, rather than only when the increment will not fit — the ACL,
    // TSIG session and message packing all live on the TCP path. The SOA
    // discloses nothing an ordinary SOA query does not.
    if query.qtype == Qtype::IXFR {
        match zones.for_query(query.qname.as_ref()) {
            Some(zone) => {
                for soa in zone.query(zone.origin(), Qtype::of(record_types::SOA)) {
                    w.push(
                        Section::Answer,
                        zone.origin(),
                        soa.class,
                        soa.ttl,
                        soa.rdata,
                    )?;
                }
            }
            None => {
                w.set_rcode(ResponseCode::Refused);
                w.set_authoritative(false);
                w.set_extended_error(NOT_OUR_ZONE);
            }
        }
        return Ok(());
    }

    // ~~One fold for the whole question, into the caller's buffer~~ (#27a,
    // #27d): the fold moved into `zone_answer` at #38, and the buffer was
    // passed to nothing until #160 deleted it. `for_query` and `zone_answer`
    // each fold onto the stack, so neither allocates.
    let Some(zone) = zones.for_query(query.qname.as_ref()) else {
        // A zone we do not serve is REFUSED, not NXDOMAIN. NXDOMAIN asserts
        // the name exists nowhere, which we have no standing to say, and a
        // resolver caches it (RFC 2308). BIND, NSD and Knot all answer
        // REFUSED here. It matters most for a *withdrawn* zone: an expired
        // secondary answering NXDOMAIN takes its zone off the internet.
        w.set_rcode(ResponseCode::Refused);
        w.set_authoritative(false);
        w.set_extended_error(NOT_OUR_ZONE);
        return Ok(());
    };

    rdns::zone_answer::write(zone, &query.qname, query.qtype, dnssec_ok, w)
}

/// RFC 1034 §4.3.2: the four cases an authoritative answer can be.
///
/// Three of the four were missing here, and the suite was green the whole time
/// because it asserted what the code did — `CLAUDE.md` §1's opening example.
/// Each test below names the wire shape that used to go out.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{make_response, nm, query, zkey, ScratchDir};
    use crate::zones::{
        load_zones, verify_zones, zone_key, ProvenSigning, SigningRun, ZoneSigning, ZoneSource,
        Zones,
    };
    use crate::{generate_keys, Cli};
    use clap::Parser;
    use rdns::clock::current_unix_timestamp;
    use rdns::dnssec::{DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE};
    use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
    use rdns::dnssec_validation_mode::DnssecValidator;
    use rdns::metrics::DnsMetrics;
    use rdns::zone::{parse_zone_file, Zone};
    use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
    use rdns::{
        record_types, Class, DnsMessage, OpCode, Qtype, QueryClass, ResourceRecord, ResponseCode,
        Rtype, Ttl,
    };
    use std::collections::{BTreeMap, HashMap};

    /// A zone with everything the algorithm has to branch on: an alias, an
    /// alias out of the zone, a two-deep wildcard, a delegation with glue,
    /// and an empty non-terminal.
    const ZONE: &str = r#"$ORIGIN example.com.
$TTL 3600
@        IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@        IN NS  ns1.example.com.
ns1      IN A   192.0.2.1
www      IN CNAME host.example.com.
host     IN A   192.0.2.10
away     IN CNAME elsewhere.test.
loop1    IN CNAME loop2.example.com.
loop2    IN CNAME loop1.example.com.
*        IN A   192.0.2.99
deep.a.b IN TXT "down here"
sub      IN NS  ns.sub.example.com.
sub      IN NS  ns.other.test.
ns.sub   IN A   192.0.2.20
redir    IN DNAME target.example.net.
inzone   IN DNAME sub2.example.com.
x.sub2   IN A   192.0.2.30
"#;

    fn server() -> Zones {
        let zone = parse_zone_file(ZONE, "example.com.").expect("the test zone parses");
        let mut zones = Zones::default();
        drop(zones.insert(zone));
        zones
    }

    fn ask(qname: &str, qtype: Qtype) -> DnsMessage {
        make_response(&query(qname, qtype, false), &server(), &DnsMetrics::new())
    }

    fn rdatas(records: &[ResourceRecord], rtype: Rtype) -> Vec<&ResourceRecord> {
        records
            .iter()
            .filter(|r| r.rdata.rtype() == rtype)
            .collect()
    }

    /// RFC 6672 §3.1 and §3.2 step 3C: a name below a DNAME gets the DNAME and
    /// a CNAME the server synthesizes from it, and the chain then continues at
    /// the substituted name.
    ///
    /// The wire shape that used to go out for every such name: NXDOMAIN, from
    /// a zone that holds the redirection and never applied it.
    #[test]
    fn a_name_below_a_dname_is_redirected_through_a_synthesized_cname() {
        let response = ask("a.redir.example.com.", Qtype::of(record_types::A));
        assert_eq!(response.rcode, ResponseCode::Ok);

        let dnames = rdatas(&response.answers, record_types::DNAME);
        assert_eq!(dnames.len(), 1, "the DNAME itself is in the answer (§3.1)");
        assert_eq!(dnames[0].name, nm("redir.example.com."));

        let cnames = rdatas(&response.answers, record_types::CNAME);
        assert_eq!(cnames.len(), 1);
        assert_eq!(
            cnames[0].name,
            nm("a.redir.example.com."),
            "§3.1: the owner name of the CNAME is the QNAME of the query"
        );
        assert_eq!(
            cnames[0].rdata.parse().unwrap(),
            ParsedRecord::CNAME(nm("a.target.example.net."))
        );
        assert_eq!(
            cnames[0].ttl, dnames[0].ttl,
            "§3.1: a CNAME with TTL equal to the corresponding DNAME RR"
        );

        // The target is out of the zone, so the chain stops there: NOERROR with
        // what we hold, never NXDOMAIN about somebody else's name.
        assert_eq!(response.answers.len(), 2);
    }

    /// RFC 6672 §2.3: "the owner name of a DNAME is not redirected itself".
    /// Table 1's second row, both halves of its `[0]`.
    #[test]
    fn the_owner_of_a_dname_is_not_redirected() {
        // QTYPE that the owner does not hold: NODATA, and §3.1 keeps the DNAME
        // out of the answer, since it is not being employed as a substitution.
        let response = ask("redir.example.com.", Qtype::of(record_types::A));
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(response.answers.is_empty(), "{:?}", response.answers);
        assert_eq!(rdatas(&response.authorities, record_types::SOA).len(), 1);

        // QTYPE = DNAME: the result is the owner name, answered from it.
        let response = ask("redir.example.com.", Qtype::of(record_types::DNAME));
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].name, nm("redir.example.com."));
        assert_eq!(response.answers[0].rdata.rtype(), record_types::DNAME);
    }

    /// A redirection whose target is inside the same zone is followed, exactly
    /// as a CNAME's is — §3.2 step 3C ends "Go back to step 1".
    #[test]
    fn a_redirection_landing_in_the_zone_is_followed_to_an_answer() {
        let response = ask("x.inzone.example.com.", Qtype::of(record_types::A));
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert_eq!(rdatas(&response.answers, record_types::DNAME).len(), 1);
        assert_eq!(rdatas(&response.answers, record_types::CNAME).len(), 1);

        let a = rdatas(&response.answers, record_types::A);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].name, nm("x.sub2.example.com."));
        assert_eq!(
            a[0].rdata.parse().unwrap(),
            ParsedRecord::A("192.0.2.30".parse().unwrap())
        );
    }

    /// The synthesized CNAME's owner is the QNAME *as asked*, because that is
    /// what a DNS-0x20 resolver compares byte for byte (RFC 1034 §4.3.3).
    #[test]
    fn a_synthesized_cname_echoes_the_case_the_client_asked_in() {
        let response = ask("A.ReDiR.example.com.", Qtype::of(record_types::A));
        let cnames = rdatas(&response.answers, record_types::CNAME);
        assert_eq!(cnames.len(), 1);
        assert_eq!(cnames[0].name, nm("A.ReDiR.example.com."));
    }

    /// RFC 6672 §2.2: "The domain name can get too long during substitution...
    /// If this occurs, the server returns an RCODE of YXDOMAIN. The DNAME
    /// record and its signature (if the zone is signed) are included in the
    /// answer as proof for the YXDOMAIN (value 6) RCODE."
    ///
    /// The RFC's own arithmetic: a target of 250 octets and a first label over
    /// five octets.
    #[test]
    fn a_substitution_over_255_octets_is_yxdomain_with_the_dname_as_proof() {
        let label = "a".repeat(49);
        let last = "a".repeat(48);
        let zone_text = format!(
            "$ORIGIN example.com.\n$TTL 3600\n\
             @ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
             @ IN NS ns1.example.com.\n\
             redir IN DNAME {label}.{label}.{label}.{label}.{last}.\n"
        );
        let zone = parse_zone_file(&zone_text, "example.com.").expect("the long zone parses");
        let mut zones = Zones::default();
        drop(zones.insert(zone));

        let response = make_response(
            &query(
                "abcdef.redir.example.com.",
                Qtype::of(record_types::A),
                false,
            ),
            &zones,
            &DnsMetrics::new(),
        );
        // RFC 2136's YXDOMAIN is 6.
        assert_eq!(response.rcode, ResponseCode::from_u16(6));
        assert_eq!(
            rdatas(&response.answers, record_types::DNAME).len(),
            1,
            "the DNAME goes out as the proof"
        );
        assert!(
            rdatas(&response.answers, record_types::CNAME).is_empty(),
            "§3.2 step 3C exits before synthesizing a CNAME"
        );

        // One label shorter and it fits, so the same zone still redirects.
        let response = make_response(
            &query("a.redir.example.com.", Qtype::of(record_types::A), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert_eq!(rdatas(&response.answers, record_types::CNAME).len(), 1);
    }

    /// RFC 6672 §2.4: "Resource records MUST NOT exist at any subdomain of the
    /// owner of a DNAME RR... If the server does load the zone, those names
    /// below the DNAME RR will be occluded as described in RFC 2136,
    /// Section 7.18."
    ///
    /// `check_dname_rules` refuses such a zone from a file, so this one is
    /// built the way a transfer or an UPDATE builds one — which is the case
    /// that check cannot reach, and the reason the redirection is applied
    /// before the name is looked up rather than after.
    #[test]
    fn a_record_below_a_dname_owner_is_occluded_not_answered() {
        let mut zone = parse_zone_file(ZONE, "example.com.").expect("the test zone parses");
        zone.add_record(rdns::zone::ZoneRecord {
            name: nm("occluded.redir.example.com."),
            ttl: Ttl::from_secs(3600),
            class: Class::IN,
            rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.66".parse().unwrap()))
                .unwrap(),
        });
        let mut zones = Zones::default();
        drop(zones.insert(zone));

        let response = make_response(
            &query(
                "occluded.redir.example.com.",
                Qtype::of(record_types::A),
                false,
            ),
            &zones,
            &DnsMetrics::new(),
        );
        assert!(
            rdatas(&response.answers, record_types::A).is_empty(),
            "the occluded record must not be served: {:?}",
            response.answers
        );
        assert_eq!(rdatas(&response.answers, record_types::DNAME).len(), 1);
        assert_eq!(rdatas(&response.answers, record_types::CNAME).len(), 1);
    }

    /// A resolver randomizes the case of the QNAME and compares the echo byte
    /// for byte; a mismatch is a spoofed answer as far as it is concerned
    /// (DNS-0x20). The answer therefore echoes the name *as asked*, not as the
    /// zone or the lookup key spells it (RFC 1034 §4.3.3, RFC 4343 on why the
    /// lookup may fold and the echo may not).
    ///
    /// Nothing tested this until #27a made the folded key a separate value from
    /// the echoed name — the two had been one string, so no test could tell them
    /// apart. Every other test here asks in lower case, where a regression is
    /// invisible.
    #[test]
    fn a_case_randomized_qname_is_echoed_exactly_as_asked() {
        // `host` is a plain A: `www` in this zone is a CNAME, whose answer
        // section ends at the target's own name and would hide the property.
        // The wildcard case is the second one — synthesis must echo the name
        // asked for, never `*.example.com.` (RFC 4592 §3.3.1).
        for asked in [
            "HoSt.eXaMpLe.CoM.",
            "AnYtHiNg.ExAmPlE.cOm.",
            "HOST.EXAMPLE.COM.",
        ] {
            let response = ask(asked, Qtype::of(record_types::A));
            assert_eq!(response.rcode, ResponseCode::Ok, "{asked}");
            assert_eq!(
                response.queries[0].qname,
                nm(asked),
                "the question is echoed as asked"
            );
            let answers = rdatas(&response.answers, record_types::A);
            assert_eq!(answers.len(), 1, "{asked}: the same record is found");
            assert_eq!(
                answers[0].name,
                nm(asked),
                "the owner name is echoed as asked, not folded"
            );
        }
    }

    /// The wire shape that used to go out for every CNAME in every zone this
    /// server loaded: an empty NOERROR with the SOA — "this name has no A
    /// record". `getaddrinfo` fails on it, and BIND and Unbound cache the
    /// NODATA and never follow the alias.
    #[test]
    fn a_cname_is_followed_to_its_target_in_the_same_zone() {
        let response = ask("www.example.com.", Qtype::of(record_types::A));

        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(response.authoritive);
        let cnames = rdatas(&response.answers, record_types::CNAME);
        assert_eq!(cnames.len(), 1, "the alias itself comes first");
        assert_eq!(cnames[0].name, nm("www.example.com."));

        let addresses = rdatas(&response.answers, record_types::A);
        assert_eq!(addresses.len(), 1, "and the data it points at");
        assert_eq!(addresses[0].name, nm("host.example.com."));
        assert!(
            response.authorities.is_empty(),
            "an answer is not a negative answer and owes no SOA"
        );
    }

    /// A chain leaving the zone stops with what we hold. NXDOMAIN here would
    /// be an assertion about a name in somebody else's zone.
    #[test]
    fn a_cname_out_of_the_zone_stops_with_the_partial_chain() {
        let response = ask("away.example.com.", Qtype::of(record_types::A));

        assert_eq!(response.rcode, ResponseCode::Ok, "not NXDOMAIN");
        assert_eq!(rdatas(&response.answers, record_types::CNAME).len(), 1);
        assert!(rdatas(&response.answers, record_types::A).is_empty());
    }

    /// A CNAME query is answered by the CNAME, not followed by it.
    #[test]
    fn a_cname_query_is_not_chased() {
        let response = ask("www.example.com.", Qtype::of(record_types::CNAME));
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata.rtype(), record_types::CNAME);
    }

    /// The referral, and the header bit that makes it one. This used to be an
    /// NXDOMAIN with AA=1, so per RFC 8020 every resolver cached "the
    /// whole subtree does not exist" and the child zone was off the internet
    /// for the negative TTL.
    #[test]
    fn a_name_below_a_delegation_gets_a_referral_not_an_nxdomain() {
        let response = ask("anything.sub.example.com.", Qtype::of(record_types::A));

        assert_eq!(
            response.rcode,
            ResponseCode::Ok,
            "a referral is not an error"
        );
        assert!(
            !response.authoritive,
            "RFC 1035 §4.1.1: AA is clear on a referral — this is the bit that \
             stopped the child zone resolving"
        );
        assert!(response.answers.is_empty());

        let ns = rdatas(&response.authorities, record_types::NS);
        assert_eq!(
            ns.len(),
            2,
            "the child's NS RRset, in the authority section"
        );
        assert!(ns.iter().all(|r| r.name == nm("sub.example.com.")));
        assert!(
            rdatas(&response.authorities, record_types::SOA).is_empty(),
            "a referral carries no SOA — it is not a negative answer"
        );

        // In-bailiwick glue only: an address for `ns.other.test.` would be an
        // assertion about a zone we do not serve.
        let glue = rdatas(&response.additionals, record_types::A);
        assert_eq!(glue.len(), 1, "{:?}", response.additionals);
        assert_eq!(glue[0].name, nm("ns.sub.example.com."));
    }

    /// A wildcard *below* the cut does not make the name exist here either,
    /// and the referral comes first.
    ///
    /// `dnssec_answer::deny_the_name_and_its_wildcard` needs
    /// `*.<closest encloser>` to be absent, or its `nsec_covering` search
    /// yields the record before a name that is in the chain and proves
    /// nothing. It said `Zone::name_kind` guaranteed that; of that function's
    /// six `NotFound` returns the delegation one does not — it returns
    /// `NotFound` because RFC 4592 §2.2.1 forbids synthesis below a cut, which
    /// says nothing about the index (`TODO.md` #79e). The guarantor is
    /// `rdns::zone_answer`'s `resolve_in_zone`, which asks `delegation_for`
    /// before anything else (RFC 1034 §4.3.2's first case), so a name under a
    /// cut never reaches a negative proof at all. This holds it end to end.
    #[test]
    fn a_wildcard_below_a_cut_is_still_a_referral() {
        let mut text = ZONE.to_string();
        text.push_str(
            "*.sub    IN A   192.0.2.77
",
        );
        let zone = parse_zone_file(&text, "example.com.").expect("occluded data parses");
        let mut zones = Zones::default();
        drop(zones.insert(zone));

        let response = make_response(
            &query("nothing.sub.example.com.", Qtype::of(record_types::A), true),
            &zones,
            &DnsMetrics::new(),
        );

        assert_eq!(response.rcode, ResponseCode::Ok, "a referral, not NXDOMAIN");
        assert!(!response.authoritive, "AA is clear on a referral");
        assert!(
            response.answers.is_empty(),
            "the wildcard below the cut is the child's data (RFC 4592 §2.2.1)"
        );
        assert_eq!(
            rdatas(&response.authorities, record_types::NS).len(),
            2,
            "the child's NS RRset is the answer"
        );
        assert!(
            rdatas(&response.authorities, record_types::NSEC).is_empty()
                && rdatas(&response.authorities, record_types::NSEC3).is_empty(),
            "and no denial is written for a name the zone never decided about"
        );
    }

    /// The wildcard at the apex must not answer for a name below the cut
    /// (RFC 4592 §2.2.1) — that name belongs to the child.
    #[test]
    fn the_delegation_wins_over_the_wildcard() {
        let response = ask("anything.sub.example.com.", Qtype::of(record_types::A));
        assert!(
            response.answers.is_empty(),
            "the apex wildcard is not this name's source of synthesis"
        );
    }

    /// A query *at* the cut is still a referral, whatever the type — except
    /// the DS, which is the parent's own statement about the child and which
    /// the child could not answer (RFC 4035 §3.1.4.1).
    #[test]
    fn a_ds_at_the_cut_is_answered_by_the_parent() {
        let mut text = ZONE.to_string();
        text.push_str(
            "sub IN DS 12345 13 2 \
             0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\n",
        );
        let zone = parse_zone_file(&text, "example.com.").unwrap();
        let mut zones = Zones::default();
        drop(zones.insert(zone));

        let response = make_response(
            &query("sub.example.com.", Qtype::of(record_types::DS), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert_eq!(rdatas(&response.answers, record_types::DS).len(), 1);
        assert!(response.authoritive, "the DS is the parent's own data");

        // Anything else at the same name is a referral.
        let ns = make_response(
            &query("sub.example.com.", Qtype::of(record_types::NS), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert!(!ns.authoritive);
        assert!(ns.answers.is_empty());
    }

    /// RFC 4592 §3.3.2: synthesis reaches any depth, not one label.
    #[test]
    fn a_wildcard_answers_a_name_more_than_one_label_deep() {
        let response = ask("a.b.c.example.com.", Qtype::of(record_types::A));
        assert_eq!(response.rcode, ResponseCode::Ok);
        let addresses = rdatas(&response.answers, record_types::A);
        assert_eq!(addresses.len(), 1);
        assert_eq!(
            addresses[0].name,
            nm("a.b.c.example.com."),
            "echoed as asked"
        );
    }

    /// RFC 4592 §2.2.2: a name with descendants exists. NXDOMAIN here is the
    /// zone taking *its own* data offline, because an RFC 8020 resolver
    /// extends the denial down to `deep.a.b`.
    #[test]
    fn an_empty_non_terminal_is_nodata_not_nxdomain() {
        let response = ask("a.b.example.com.", Qtype::of(record_types::TXT));
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(response.answers.is_empty());
        assert_eq!(rdatas(&response.authorities, record_types::SOA).len(), 1);
    }

    /// RFC 2308 §3: `min(SOA MINIMUM, the SOA record's own TTL)`. The zone
    /// above is the shape this repo's own tests use — `$TTL 3600`,
    /// `minimum 300` — so sending the record's own TTL advertised every "no"
    /// at 3600 where the RFC says 300, cached 12× longer than the operator
    /// asked for.
    #[test]
    fn a_negative_answer_caps_the_soa_ttl_at_minimum() {
        for (qname, qtype, what) in [
            ("a.b.example.com.", record_types::TXT, "NODATA"),
            ("x.a.b.example.com.", record_types::A, "NXDOMAIN"),
        ] {
            let response = ask(qname, Qtype::of(qtype));
            let soa = rdatas(&response.authorities, record_types::SOA);
            assert_eq!(soa.len(), 1, "{what}");
            assert_eq!(
                soa[0].ttl,
                Ttl::from_secs(300),
                "{what}: capped at MINIMUM, not the $TTL"
            );
        }
    }

    /// The same rule the other way round, which the zone above cannot show:
    /// its `$TTL` is the larger of the two, so a cap computed from MINIMUM
    /// alone gives the right number there and the direction #73 got wrong goes
    /// untested. Watched failing against `Ttl::negative_answer` returning
    /// `minimum` (`CLAUDE.md` §1).
    #[test]
    fn a_negative_answer_caps_minimum_at_the_soa_ttl() {
        const SHORT_SOA_TTL: &str = r#"$ORIGIN example.com.
$TTL 60
@   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 3600 )
@   IN NS  ns1.example.com.
ns1 IN A   192.0.2.1
"#;
        let zone = parse_zone_file(SHORT_SOA_TTL, "example.com.").expect("the fixture parses");
        let mut zones = Zones::default();
        drop(zones.insert(zone));
        let response = make_response(
            &query("nope.example.com.", Qtype::of(record_types::A), false),
            &zones,
            &DnsMetrics::new(),
        );

        assert_eq!(response.rcode, ResponseCode::NoSuchDomain);
        let soa = rdatas(&response.authorities, record_types::SOA);
        assert_eq!(soa.len(), 1);
        assert_eq!(
            soa[0].ttl,
            Ttl::from_secs(60),
            "capped at the SOA's own TTL, not at MINIMUM"
        );
    }

    /// And the NXDOMAIN that is still an NXDOMAIN, so the fixes above did not
    /// turn every name into a hit: `x.a.b` is below an existing name, so the
    /// apex wildcard is not its source of synthesis and nothing answers.
    #[test]
    fn a_name_nothing_reaches_is_still_nxdomain() {
        let response = ask("x.a.b.example.com.", Qtype::of(record_types::A));
        assert_eq!(response.rcode, ResponseCode::NoSuchDomain);
        assert!(response.authoritive, "we are authoritative for saying no");
        assert_eq!(rdatas(&response.authorities, record_types::SOA).len(), 1);
    }

    /// The class was stored, parsed and then never compared, so a CH
    /// question was answered out of the IN zone — putting `CLASS=CH` in the
    /// echoed question next to `CLASS=IN` records in the answer, a pairing
    /// no resolver can make sense of. RFC 1034 §4.3.2 step 1 searches the
    /// zones *of the question's class*, and there are none.
    ///
    /// REFUSED rather than NXDOMAIN for the reason the rest of this file
    /// gives: NXDOMAIN is an assertion about the DNS that a server holding
    /// nothing in that class has no standing to make, and resolvers cache it.
    #[test]
    fn a_class_this_server_does_not_serve_is_refused() {
        for class in [QueryClass::CH, QueryClass::HS, QueryClass::Other(99)] {
            let mut msg = query("example.com.", Qtype::of(record_types::SOA), false);
            msg.queries[0].qclass = class;
            let response = make_response(&msg, &server(), &DnsMetrics::new());

            assert_eq!(response.rcode, ResponseCode::Refused, "{class:?}");
            assert!(!response.authoritive, "{class:?}");
            assert!(
                response.answers.is_empty(),
                "{class:?}: an IN record must not answer a {class:?} question"
            );
            assert_eq!(
                response.queries[0].qclass, class,
                "{class:?}: the question is echoed as it was asked"
            );
        }
    }

    /// Every refusal this path can give says why (RFC 8914), and says it only
    /// to a client that sent an OPT to carry it (§2).
    ///
    /// A bare REFUSED is a support ticket: an operator cannot tell "you asked
    /// the wrong server" from "your key is scoped elsewhere" from "that class
    /// is not served" without one. The three sites share two INFO-CODEs on
    /// purpose — the registry is coarser than the reasons — so the text is
    /// what separates them.
    #[test]
    fn a_refusal_says_why_when_the_client_can_hear_it() {
        let mut wrong_class = query("example.com.", Qtype::of(record_types::SOA), false);
        wrong_class.queries[0].qclass = QueryClass::CH;
        let mut notify = query("example.com.", Qtype::of(record_types::SOA), false);
        notify.opcode = OpCode::Notify;

        for (request, rcode, expected) in [
            (
                query("nothing.here.test.", Qtype::of(record_types::A), false),
                ResponseCode::Refused,
                InfoCode::NOT_AUTHORITATIVE,
            ),
            (wrong_class, ResponseCode::Refused, InfoCode::NOT_SUPPORTED),
            (
                notify,
                ResponseCode::NotImplemented,
                InfoCode::NOT_SUPPORTED,
            ),
        ] {
            let response = make_response(&request, &server(), &DnsMetrics::new());
            assert_eq!(response.rcode, rcode);
            let edns = response.edns.as_ref().expect("the OPT is mirrored");
            let errors = ExtendedError::all_in(edns).expect("a well-formed option list");
            assert_eq!(
                errors.iter().map(|(code, _)| *code).collect::<Vec<_>>(),
                vec![expected],
                "{rcode:?}"
            );

            // The same question without an OPT: no OPT, so nowhere to put it.
            let mut plain = request.clone();
            plain.edns = None;
            let response = make_response(&plain, &server(), &DnsMetrics::new());
            assert_eq!(response.rcode, rcode);
            assert!(
                response.edns.is_none(),
                "{rcode:?}: an unsolicited OPT is not mirroring (RFC 6891 §6.1.1)"
            );
        }
    }

    /// Two questions is FORMERR (RFC 9619 §4), not two answers.
    ///
    /// This server used to loop over the question section and pile every
    /// answer into one message, which has no meaning: there is one RCODE, one
    /// AA bit and one set of sections, so a NOERROR answer and an NXDOMAIN in
    /// the same reply are indistinguishable from an answer and a NODATA. The
    /// last question's outcome simply won. §4 makes it explicit — "A DNS
    /// message with OPCODE = 0 MUST NOT include a QDCOUNT parameter whose
    /// value is greater than 1", to "be treated as an incorrectly formatted
    /// message" — and BIND, NSD, Knot and Unbound all did this already.
    ///
    /// So is no question at all, and that is the half this test had wrong
    /// (`TODO.md` #78c). It asserted an empty NOERROR on the strength of §4's
    /// other sentence — "Such firewalls MUST NOT treat messages with
    /// OPCODE = 0 and QDCOUNT = 0 as malformed" — which is addressed to
    /// middleboxes deciding what to forward, not to responders deciding what to
    /// answer, and which said nothing about the AA bit this server was setting
    /// over an empty question section.
    #[test]
    fn two_questions_in_one_query_are_a_format_error() {
        let mut msg = query("www.example.com.", Qtype::of(record_types::A), false);
        msg.queries.push(rdns::QuerySection {
            qname: nm("host.example.com."),
            qtype: Qtype::of(record_types::A),
            qclass: QueryClass::IN,
        });
        let response = make_response(&msg, &server(), &DnsMetrics::new());

        assert_eq!(response.rcode, ResponseCode::FormatError);
        assert!(!response.authoritive);
        assert!(response.answers.is_empty(), "neither question is answered");
        assert_eq!(response.queries.len(), 2, "both are echoed back");

        let none = {
            let mut msg = query("www.example.com.", Qtype::of(record_types::A), false);
            msg.queries.clear();
            make_response(&msg, &server(), &DnsMetrics::new())
        };
        assert_eq!(none.rcode, ResponseCode::FormatError, "nothing to look up");
        assert!(
            !none.authoritive,
            "AA names the question section's domain (RFC 1035 §4.1.1), and there is none"
        );
        assert!(none.answers.is_empty());
    }

    /// Choosing a zone folds ASCII case and nothing else (RFC 4343), which
    /// is what the zone index inside it has always done.
    ///
    /// The lookup lower-cased both sides with `str::to_lowercase`
    /// — the full Unicode mapping, which folds U+212A KELVIN SIGN to `k`. A
    /// query for `\u{212A}.example.com.` therefore *selected* the zone
    /// `k.example.com.`, two names that are different bytes on the wire. The
    /// lookup inside then folded ASCII, found nothing, and the answer went
    /// out as NXDOMAIN with AA set — an assertion that a name does not
    /// exist anywhere, made by a server with no standing to make it, and
    /// cached by every resolver that hears it (`CLAUDE.md` §8). REFUSED is
    /// the answer for a name we hold no zone for.
    #[test]
    fn choosing_a_zone_folds_ascii_case_and_nothing_else() {
        let zone = parse_zone_file(
            "$ORIGIN k.example.com.\n\
             $TTL 3600\n\
             @ IN SOA ns1.k.example.com. admin.k.example.com. ( 1 3600 600 604800 300 )\n\
             @ IN NS  ns1.k.example.com.\n",
            "k.example.com.",
        )
        .expect("the test zone parses");
        let mut zones = Zones::default();
        drop(zones.insert(zone));

        let refused = make_response(
            &query("\u{212A}.example.com.", Qtype::of(record_types::SOA), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert_eq!(refused.rcode, ResponseCode::Refused);
        assert!(!refused.authoritive);

        // ASCII case still folds, which is the half that has to keep
        // working: this is the same zone asked for in the other case.
        let answered = make_response(
            &query("K.Example.COM.", Qtype::of(record_types::SOA), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert_eq!(answered.rcode, ResponseCode::Ok);
        assert!(answered.authoritive);
        assert_eq!(rdatas(&answered.answers, record_types::SOA).len(), 1);
    }

    /// A child zone answers for its own names even when its parent is served
    /// here too — the most specific zone wins, which is what the walk finds
    /// first and what the scan's `max_by_key` found by length.
    ///
    /// Preventative, not a regression (§10): both spellings of the lookup get
    /// this right. It is here because the walk is the *only* thing that decides
    /// it now, and a walk that started at the apex instead of the QNAME would
    /// pass every other test in this file.
    #[test]
    fn the_child_zone_answers_for_names_below_the_cut() {
        let parent = parse_zone_file(ZONE, "example.com.").expect("the parent zone parses");
        let child = parse_zone_file(
            "$ORIGIN sub.example.com.\n\
             $TTL 3600\n\
             @   IN SOA ns.sub.example.com. admin.sub.example.com. ( 1 3600 600 604800 300 )\n\
             @   IN NS  ns.sub.example.com.\n\
             ns  IN A   192.0.2.20\n\
             www IN A   192.0.2.21\n",
            "sub.example.com.",
        )
        .expect("the child zone parses");
        let mut zones = Zones::default();
        drop(zones.insert(parent));
        drop(zones.insert(child));

        let from_child = make_response(
            &query("www.sub.example.com.", Qtype::of(record_types::A), false),
            &zones,
            &DnsMetrics::new(),
        );
        // From the parent this name is below a delegation, so a referral with AA
        // clear is what selecting the wrong zone looks like.
        assert!(
            from_child.authoritive,
            "answered from the child, not referred"
        );
        assert_eq!(rdatas(&from_child.answers, record_types::A).len(), 1);

        let from_parent = make_response(
            &query("host.example.com.", Qtype::of(record_types::A), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert!(from_parent.authoritive);
        assert_eq!(rdatas(&from_parent.answers, record_types::A).len(), 1);
    }

    /// QTYPE=ANY is 255, which is a QTYPE and never an RTYPE, so the strict
    /// `r.rdata.rtype() == qtype` matched nothing and an existing
    /// name came back as an empty NOERROR plus the SOA. That is a NODATA for
    /// a name that plainly has data, and it is none of the shapes RFC 8482
    /// §4 permits — not the conventional full answer, not §4.2's synthesized
    /// HINFO, not a single-RRset subset. RFC 1035 §3.2.3 defines it as "all
    /// records", which is the shape taken here.
    #[test]
    fn qtype_any_returns_every_rrset_at_the_name() {
        let response = ask("example.com.", Qtype::of(record_types::ANY));

        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(response.authoritive);
        assert_eq!(
            rdatas(&response.answers, record_types::SOA).len(),
            1,
            "the apex SOA"
        );
        assert_eq!(
            rdatas(&response.answers, record_types::NS).len(),
            1,
            "and the apex NS beside it, in one answer"
        );
        assert!(
            response.authorities.is_empty(),
            "an answer is not a negative answer and owes no SOA in authority"
        );
    }

    /// A name holding one type still answers with just that type, so the
    /// change did not turn ANY into "everything in the zone".
    #[test]
    fn qtype_any_at_a_single_type_name_returns_only_that_type() {
        let response = ask("host.example.com.", Qtype::of(record_types::ANY));
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata.rtype(), record_types::A);
    }

    /// A CNAME is the only type at its owner (RFC 1034 §3.6.2), so ANY
    /// answers with the alias itself rather than chasing it — the chase is
    /// for a QTYPE the alias does not hold, and ANY holds everything.
    #[test]
    fn qtype_any_at_an_alias_answers_with_the_alias() {
        let response = ask("www.example.com.", Qtype::of(record_types::ANY));
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata.rtype(), record_types::CNAME);
        assert_eq!(response.answers[0].name, nm("www.example.com."));
    }

    /// And a name that does not exist is still NXDOMAIN under ANY: matching
    /// every type must not become matching every name.
    #[test]
    fn qtype_any_at_a_missing_name_is_still_a_negative_answer() {
        let response = ask("x.a.b.example.com.", Qtype::of(record_types::ANY));
        assert_eq!(response.rcode, ResponseCode::NoSuchDomain);
        assert!(response.answers.is_empty());
        assert_eq!(rdatas(&response.authorities, record_types::SOA).len(), 1);
    }

    /// QCLASS=ANY is not an unserved class: RFC 1035 §3.2.5 makes `*` match
    /// any class, and IN is the only class there is here. Refusing it would
    /// be the fix overshooting the bug.
    #[test]
    fn qclass_any_is_answered_from_the_in_zone() {
        let mut msg = query("example.com.", Qtype::of(record_types::SOA), false);
        msg.queries[0].qclass = QueryClass::Any;
        let response = make_response(&msg, &server(), &DnsMetrics::new());

        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(response.authoritive);
        assert_eq!(rdatas(&response.answers, record_types::SOA).len(), 1);
    }

    // Signing, and answering a client that can read the result

    mod dnssec {
        use super::*;
        use rdns::dnssec::{dnskeys_in, rrsigs_in, verify_rrset, Dnskey, Rrset, RrsetProof};
        use rdns::dnssec_denial::{
            nsec3s_in, nsecs_in, proves_no_ds, proves_nxdomain, proves_wildcard_expansion, Denial,
            WildcardVerdict,
        };
        use rdns::zone::parse_zone_file;
        use rdns::RecordData;

        const SIGNED_ZONE: &str = r#"$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@   IN NS  ns1.example.com.
ns1 IN A   192.0.2.1
www IN A   192.0.2.10
deep.a.b IN TXT "down here"
"#;

        /// A server holding one signed zone, and the keys it was signed with.
        fn signed_server(nsec3: bool) -> (Zones, Vec<SigningKey>) {
            let keys = vec![
                SigningKey::generate(
                    SigningAlgorithm::EcdsaP256Sha256,
                    "example.com.",
                    DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
                )
                .unwrap(),
                SigningKey::generate(
                    SigningAlgorithm::EcdsaP256Sha256,
                    "example.com.",
                    DNSKEY_FLAG_ZONE,
                )
                .unwrap(),
            ];
            let policy = SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400)
                .with_chain(if nsec3 {
                    DenialChain::nsec3()
                } else {
                    DenialChain::Nsec
                });
            let zone = sign_zone(
                &parse_zone_file(SIGNED_ZONE, "example.com.").unwrap(),
                &keys,
                &policy,
            )
            .unwrap();
            let mut zones = Zones::default();
            drop(zones.insert(zone));
            (zones, keys)
        }

        fn keys_of(zones: &Zones) -> Vec<Dnskey> {
            let zone = &zones[zkey("example.com.").as_slice()];
            dnskeys_in(
                &zone
                    .query(nm("example.com.").as_ref(), Qtype::of(record_types::DNSKEY))
                    .into_iter()
                    .map(|r| ResourceRecord {
                        name: r.name.to_owned(),
                        class: r.class,
                        ttl: r.ttl,
                        rdata: r.rdata.to_owned(),
                    })
                    .collect::<Vec<_>>(),
            )
        }

        /// A zone with a wildcard and both kinds of delegation, which is what the
        /// referral and deep-synthesis proofs need and what `SIGNED_ZONE` above
        /// deliberately does not have — a wildcard at the apex would turn its
        /// NXDOMAIN tests into wildcard answers.
        const DELEGATING_ZONE: &str = r#"$ORIGIN example.com.
$TTL 3600
@         IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@         IN NS  ns1.example.com.
ns1       IN A   192.0.2.1
*         IN A   192.0.2.99
secure    IN NS  ns.secure.example.com.
secure    IN DS  12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns.secure IN A   192.0.2.20
plain     IN NS  ns.plain.example.com.
ns.plain  IN A   192.0.2.30
"#;

        fn signed_zones(text: &str, nsec3: bool) -> (Zones, Vec<SigningKey>) {
            let keys = vec![
                SigningKey::generate(
                    SigningAlgorithm::EcdsaP256Sha256,
                    "example.com.",
                    DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
                )
                .unwrap(),
                SigningKey::generate(
                    SigningAlgorithm::EcdsaP256Sha256,
                    "example.com.",
                    DNSKEY_FLAG_ZONE,
                )
                .unwrap(),
            ];
            let policy = SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400)
                .with_chain(if nsec3 {
                    DenialChain::nsec3()
                } else {
                    DenialChain::Nsec
                });
            let zone = sign_zone(
                &parse_zone_file(text, "example.com.").unwrap(),
                &keys,
                &policy,
            )
            .unwrap();
            let mut zones = Zones::default();
            drop(zones.insert(zone));
            (zones, keys)
        }

        /// The failure this is the regression test for: a signed zone with a
        /// wildcard SERVFAILed at every validator for every non-existent name two
        /// or more labels deep. The synthesis reached one label, so a deeper
        /// name became an NXDOMAIN — and then the wildcard denial asked the chain
        /// to cover `*.example.com.`, a name that is *in* the chain, so nothing
        /// covered it and the proof came back unproved. Failing closed is worse
        /// than failing open here: the zone was unusable rather than merely
        /// wrong.
        #[test]
        fn a_deep_wildcard_answer_verifies_and_proves_its_own_expansion() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(DELEGATING_ZONE, nsec3);
                let qname = "x.y.z.example.com.";
                let response = make_response(
                    &query(qname, Qtype::of(record_types::A), true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert_eq!(response.rcode, ResponseCode::Ok, "nsec3={nsec3}");
                let rdatas: Vec<RecordData> = response
                    .answers
                    .iter()
                    .filter(|r| r.rdata.rtype() == record_types::A)
                    .map(|r| r.rdata.clone())
                    .collect();
                assert_eq!(rdatas.len(), 1, "nsec3={nsec3}: no wildcard answer");

                let proof = verify_rrset(
                    &Rrset::new(nm(qname).as_ref(), record_types::A, Class::IN, &rdatas),
                    &rrsigs_in(&response.answers),
                    &keys_of(&zones),
                    nm("example.com.").as_ref(),
                    current_unix_timestamp(),
                );
                let RrsetProof::Verified {
                    wildcard: Some(wildcard),
                    ..
                } = proof
                else {
                    panic!("nsec3={nsec3}: expected a wildcard expansion, got {proof:?}");
                };
                assert_eq!(wildcard, nm("*.example.com."));

                // And the denial it owes: without it one captured answer is a
                // valid answer for every name the wildcard reaches
                // (RFC 4035 §3.1.3).
                let verdict = proves_wildcard_expansion(
                    nm(qname).as_ref(),
                    wildcard.as_ref(),
                    &nsecs_in(&response.authorities),
                    &nsec3s_in(&response.authorities),
                );
                assert!(
                    matches!(verdict, WildcardVerdict::Proved),
                    "nsec3={nsec3}: {verdict:?}"
                );
            }
        }

        /// An ANY answer from a signed zone owes a signature over every
        /// RRset it returns, and the filter that finds them was
        /// `sig.type_covered != qtype` — which matches nothing for QTYPE 255,
        /// because no RRSIG covers a QTYPE. Left alone, making ANY return every
        /// type would have handed a validator the whole of a signed name's data
        /// with no signatures on it at all: bogus, not merely unsigned, and a
        /// SERVFAIL for the name.
        ///
        /// Judged with `verify_rrset` — the same code that judges a real zone
        /// off the internet — rather than by counting RRSIG records, because a
        /// signature that is present and does not verify passes a count
        /// (`CLAUDE.md` §1).
        #[test]
        fn an_any_answer_from_a_signed_zone_is_signed_rrset_by_rrset() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(SIGNED_ZONE, nsec3);
                let response = make_response(
                    &query("example.com.", Qtype::of(record_types::ANY), true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert_eq!(response.rcode, ResponseCode::Ok, "nsec3={nsec3}");

                // Every type the apex actually holds must be in the answer, and
                // the DNSSEC meta types must not: RFC 4035 §3.1.1 keeps NSEC and
                // the signatures out of the answer section, and an NSEC there
                // would also make an empty non-terminal look like data.
                for rtype in [record_types::SOA, record_types::NS, record_types::DNSKEY] {
                    assert!(
                        response.answers.iter().any(|r| r.rdata.rtype() == rtype),
                        "nsec3={nsec3}: type {rtype} missing from the ANY answer"
                    );
                }
                assert!(
                    !response.answers.iter().any(|r| matches!(
                        r.rdata.rtype(),
                        record_types::NSEC | record_types::NSEC3
                    )),
                    "nsec3={nsec3}: a denial record is not answer-section data"
                );

                // Then the part that matters: each RRset, against the zone's own
                // keys.
                let signatures = rrsigs_in(&response.answers);
                let keys = keys_of(&zones);
                for rtype in [record_types::SOA, record_types::NS, record_types::DNSKEY] {
                    let rdatas: Vec<RecordData> = response
                        .answers
                        .iter()
                        .filter(|r| r.rdata.rtype() == rtype)
                        .map(|r| r.rdata.clone())
                        .collect();
                    let proof = verify_rrset(
                        &Rrset::new(nm("example.com.").as_ref(), rtype, Class::IN, &rdatas),
                        &signatures,
                        &keys,
                        nm("example.com.").as_ref(),
                        current_unix_timestamp(),
                    );
                    assert!(
                        matches!(proof, RrsetProof::Verified { .. }),
                        "nsec3={nsec3}: type {rtype} in an ANY answer: {proof:?}"
                    );
                }
            }
        }

        /// And without DO, an ANY answer carries the data and nothing else — the
        /// signatures are not volunteered to a client that did not ask for them
        /// (RFC 4035 §3.1.1), which is the other half of the same rule.
        #[test]
        fn an_any_answer_without_do_carries_no_dnssec_records() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(SIGNED_ZONE, nsec3);
                let response = make_response(
                    &query("example.com.", Qtype::of(record_types::ANY), false),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert_eq!(response.rcode, ResponseCode::Ok, "nsec3={nsec3}");
                assert!(
                    !response.answers.iter().any(|r| matches!(
                        r.rdata.rtype(),
                        record_types::RRSIG | record_types::NSEC | record_types::NSEC3
                    )),
                    "nsec3={nsec3}: DNSSEC records went out to a client that did not set DO"
                );
                assert!(
                    response
                        .answers
                        .iter()
                        .any(|r| r.rdata.rtype() == record_types::SOA),
                    "nsec3={nsec3}: but the zone's own data is still there"
                );
            }
        }

        /// A secure delegation hands down the DS and its signature, and the NS
        /// RRset goes out unsigned — it is the child's data (RFC 4035 §2.2).
        #[test]
        fn a_secure_referral_carries_the_ds_and_leaves_the_ns_rrset_unsigned() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(DELEGATING_ZONE, nsec3);
                let response = make_response(
                    &query("host.secure.example.com.", Qtype::of(record_types::A), true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert!(!response.authoritive, "nsec3={nsec3}");
                let ds: Vec<RecordData> = response
                    .authorities
                    .iter()
                    .filter(|r| r.rdata.rtype() == record_types::DS)
                    .map(|r| r.rdata.clone())
                    .collect();
                assert_eq!(
                    ds.len(),
                    1,
                    "nsec3={nsec3}: the DS is what continues the chain"
                );

                let sigs = rrsigs_in(&response.authorities);
                let proof = verify_rrset(
                    &Rrset::new(
                        nm("secure.example.com.").as_ref(),
                        record_types::DS,
                        Class::IN,
                        &ds,
                    ),
                    &sigs,
                    &keys_of(&zones),
                    nm("example.com.").as_ref(),
                    current_unix_timestamp(),
                );
                assert!(
                    matches!(proof, RrsetProof::Verified { .. }),
                    "nsec3={nsec3}: an unsigned DS proves nothing: {proof:?}"
                );
                assert!(
                    !sigs.iter().any(|s| s.type_covered == record_types::NS),
                    "nsec3={nsec3}: the delegation's NS RRset must not be signed — every \
                     validator ignores the signature and the type shows up in the parent's \
                     bitmap as one that is not there"
                );
            }
        }

        /// An insecure delegation is the other half, and the more dangerous one:
        /// "there is no DS here" has to be *proved*, or stripping the DS is a
        /// downgrade to insecure and anything in the child may then be forged.
        #[test]
        fn an_insecure_referral_carries_a_signed_denial_of_the_ds() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(DELEGATING_ZONE, nsec3);
                let response = make_response(
                    &query("host.plain.example.com.", Qtype::of(record_types::A), true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert!(!response.authoritive, "nsec3={nsec3}");
                assert!(
                    !response
                        .authorities
                        .iter()
                        .any(|r| r.rdata.rtype() == record_types::DS),
                    "nsec3={nsec3}: this child is not signed"
                );
                let denial = proves_no_ds(
                    nm("plain.example.com.").as_ref(),
                    &nsecs_in(&response.authorities),
                    &nsec3s_in(&response.authorities),
                );
                assert!(
                    matches!(denial, Denial::Proved),
                    "nsec3={nsec3}: {denial:?}"
                );
            }
        }

        #[test]
        fn a_do_query_gets_an_answer_a_validator_accepts() {
            let (zones, _keys) = signed_server(false);
            let metrics = DnsMetrics::new();
            let response = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), true),
                &zones,
                &metrics,
            );

            // Judge it the way a client would: only what came back.
            let rdatas: Vec<RecordData> = response
                .answers
                .iter()
                .filter(|r| r.rdata.rtype() == record_types::A)
                .map(|r| r.rdata.clone())
                .collect();
            let proof = verify_rrset(
                &Rrset::new(
                    nm("www.example.com.").as_ref(),
                    record_types::A,
                    Class::IN,
                    &rdatas,
                ),
                &rrsigs_in(&response.answers),
                &keys_of(&zones),
                nm("example.com.").as_ref(),
                current_unix_timestamp(),
            );
            assert!(matches!(proof, RrsetProof::Verified { .. }), "{proof:?}");
        }

        #[test]
        fn a_do_query_for_a_name_that_is_not_there_gets_the_proof() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_server(nsec3);
                let metrics = DnsMetrics::new();
                let response = make_response(
                    &query("gone.a.b.example.com.", Qtype::of(record_types::A), true),
                    &zones,
                    &metrics,
                );
                assert_eq!(response.rcode, ResponseCode::NoSuchDomain);

                let denial = proves_nxdomain(
                    nm("gone.a.b.example.com.").as_ref(),
                    nm("example.com.").as_ref(),
                    &nsecs_in(&response.authorities),
                    &nsec3s_in(&response.authorities),
                );
                assert!(
                    matches!(denial, Denial::Proved),
                    "nsec3={nsec3}: {denial:?}"
                );
            }
        }

        #[test]
        fn a_client_that_did_not_ask_gets_no_dnssec_records() {
            // The DO bit is what says the client can read them. Sending them
            // anyway is bytes on an amplification path for a client that will
            // ignore them, and a response that may no longer fit a datagram.
            let (zones, _keys) = signed_server(false);
            let metrics = DnsMetrics::new();

            let answer = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), false),
                &zones,
                &metrics,
            );
            assert!(rrsigs_in(&answer.answers).is_empty());
            assert!(!answer.edns().unwrap().do_bit);

            let denial = make_response(
                &query("nope.example.com.", Qtype::of(record_types::A), false),
                &zones,
                &metrics,
            );
            assert!(nsecs_in(&denial.authorities).is_empty());
            // The SOA is still there: a negative answer has always carried one
            // (RFC 2308), signed zone or not.
            assert!(denial
                .authorities
                .iter()
                .any(|r| r.rdata.rtype() == record_types::SOA));
        }

        #[test]
        fn the_do_bit_comes_back_set() {
            // RFC 3225 §3. Without it the client cannot tell an answer with no
            // DNSSEC records from a server that dropped them.
            let (zones, _keys) = signed_server(false);
            let metrics = DnsMetrics::new();
            let response = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), true),
                &zones,
                &metrics,
            );
            assert!(response.edns().unwrap().do_bit);
        }

        #[test]
        fn an_unsigned_zone_answers_a_do_query_the_way_it_answers_any_other() {
            let mut zones = Zones::default();
            drop(zones.insert(parse_zone_file(SIGNED_ZONE, "example.com.").unwrap()));
            let metrics = DnsMetrics::new();

            let response = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), true),
                &zones,
                &metrics,
            );
            assert_eq!(response.answers.len(), 1);
            assert!(rrsigs_in(&response.answers).is_empty());
        }

        #[test]
        fn keys_are_generated_loaded_and_used_without_anything_in_between() {
            // The whole operator path in one test: make the keys, point the
            // server at the directory, and have what it serves verify. Each
            // step is checked elsewhere; what this catches is the two ends not
            // meeting — a key written under a name the loader does not look
            // for, or loaded for a zone whose origin is spelled differently.
            let dir = ScratchDir::new("signing");
            generate_keys("example.com", dir.path(), "ECDSAP256SHA256").expect("generate");

            let zone_path = dir.join("example.com.zone");
            std::fs::write(&zone_path, SIGNED_ZONE).unwrap();

            let cli = Cli::parse_from([
                "rdnsd",
                "--zone-dir",
                dir.path().to_str().unwrap(),
                "--signing-key-dir",
                dir.path().to_str().unwrap(),
            ]);
            let signing = ZoneSigning::load(&cli, &BTreeMap::new())
                .expect("load keys")
                .expect("configured");

            let mut zones = load_zones(
                &ZoneSource::Directory(dir.path().to_string_lossy().to_string()),
                false,
                false,
                None,
            )
            .map(|l| l.zones)
            .expect("zones");
            let run = signing.apply(&mut zones, None).expect("sign");

            // Checked with the same validator the server runs before serving.
            let mut validator = DnssecValidator::new(true);
            validator.set_require_signed(true);
            let proved = ProvenSigning::default();
            verify_zones(&zones, &validator, &run, &proved)
                .expect("the zone we just signed verifies");

            // And the same zones again, without re-signing: the run is the same
            // and the keys have not moved, so nothing is checked a second time
            // (`TODO.md` #53).
            assert_eq!(
                verify_zones(&zones, &validator, &run, &proved).expect("verifies"),
                crate::zones::Checked {
                    zones: 0,
                    rrsets: 0,
                    skipped: 1,
                    resigned: 0,
                },
            );

            let zones = Zones::new(zones);
            let metrics = DnsMetrics::new();
            let response = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), true),
                &zones,
                &metrics,
            );
            assert_eq!(rrsigs_in(&response.answers).len(), 1);
        }

        #[test]
        fn require_signed_refuses_an_unsigned_zone_rather_than_serving_it() {
            let zone = parse_zone_file(SIGNED_ZONE, "example.com.").unwrap();
            let mut zones = HashMap::new();
            zones.insert(zone_key(&zone), std::sync::Arc::new(zone));

            let mut validator = DnssecValidator::new(true);
            validator.set_require_signed(true);
            let err = verify_zones(
                &zones,
                &validator,
                &SigningRun::default(),
                &ProvenSigning::default(),
            )
            .unwrap_err();
            assert!(err.to_string().contains("not signed"), "{err}");

            // And without the assertion, the same zone is fine: most zones are
            // unsigned and serving them is the normal case.
            let permissive = DnssecValidator::new(true);
            assert!(verify_zones(
                &zones,
                &permissive,
                &SigningRun::default(),
                &ProvenSigning::default()
            )
            .is_ok());
        }

        #[test]
        fn a_signature_that_stopped_matching_its_records_stops_the_server() {
            // The failure this check exists for: the zone file was edited and
            // the signatures were not renewed, so what goes out is signed data
            // that no longer says what the signature says it says.
            let (mut zones, _keys) = signed_server(false);
            let edited = {
                let zone = zones
                    .matching(nm("example.com.").as_ref())
                    .expect("the signed zone");
                let mut edited = Zone::new(nm(&zone.origin().to_string()));
                for record in zone.records() {
                    let mut record = record.to_owned();
                    if record.name == nm("www.example.com.")
                        && record.rdata.rtype() == record_types::A
                    {
                        record.rdata = RecordData::from_parsed(&rdns::ParsedRecord::A(
                            "198.51.100.9".parse().unwrap(),
                        ))
                        .unwrap();
                    }
                    edited.add_record(record.to_owned());
                }
                edited
            };
            drop(zones.insert(edited));

            let validator = DnssecValidator::new(true);
            let err = verify_zones(
                &zones,
                &validator,
                &SigningRun::default(),
                &ProvenSigning::default(),
            )
            .unwrap_err();
            assert!(err.to_string().contains("does not verify"), "{err}");
        }
    }
}
