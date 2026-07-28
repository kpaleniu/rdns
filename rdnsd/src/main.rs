use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use rdns::{
    dnssec::{DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE},
    dnssec_answer,
    dnssec_key::{SigningAlgorithm, SigningKey},
    dnssec_validation_mode::DnssecValidator,
    ixfr::{ixfr_response, DeltaLog, IxfrResponse},
    logging::QueryLogger,
    notify,
    secondary::{
        is_newer, state_file_path, zone_file_path, MasterSpec, RefreshTimers, StateFile,
        TransferState,
    },
    security::{RateLimiter, ResponseLimiter, ResponseVerdict, TransferAcl},
    transfer::axfr_messages,
    tsig::{self, TsigAlgorithm, TsigCheck, TsigKey, TsigKeyring, TsigSession},
    OpCode,
    telemetry::{instrumentation, DnsMetrics, LatencyTimer},
    utils::{current_unix_timestamp, record_types, recv_error_is_transient, UDP_RECEIVE_BUFFER},
    validation::RequestValidator,
    xfr,
    zone::{parse_zone_file_at, NameKind, Zone},
    zone_signer::{sign_zone, DenialChain, SigningPolicy},
    zone_writer::write_zone_file,
    DnsMessage, Edns, ResourceRecord, ResponseCode, EDNS_VERSION,
};

/// UDP payload size rdnsd advertises to clients via EDNS0.
const RDNSD_PAYLOAD_SIZE: u16 = 4096;

/// How long a TCP connection may sit idle between queries before we close it.
/// RFC 7766 §6.2.3 wants connections reused rather than reopened; an idle one
/// still costs a socket, so this is the compromise.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long we wait for the rest of a message once its length prefix arrived.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on concurrent TCP connections. Without one, an accept loop that
/// spawns per connection is a free file-descriptor exhaustion vector.
const MAX_TCP_CONNECTIONS: usize = 128;

/// Queries a single connection may have in flight at once. Doubles as the reply
/// channel's depth, so a client that pipelines faster than it reads eventually
/// pushes back on our read loop instead of growing a queue in memory.
const MAX_INFLIGHT_PER_CONNECTION: usize = 16;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify, RwLock, Semaphore};

#[cfg(unix)]
use signal_hook::consts::signal::SIGHUP;
#[cfg(unix)]
use signal_hook_tokio::Signals;

/// Authoritative DNS server.
///
/// Serves UDP *and* TCP from one process. It used to be one process per transport
/// — `rdnsd udp` beside `rdnsd tcp` over the same zone files — which was harmless
/// only while zones were read-only. Anything that writes state (a fetched zone, a
/// refresh timestamp) needs a single owner, and two servers racing to write the
/// same zone file is not a design to grow into.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Address to listen on, for both transports.
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    /// Port to listen on, for both transports.
    #[arg(long, default_value = "53")]
    port: u16,
    /// A single zone file. The origin comes from the file name.
    #[arg(long)]
    zone_file: Option<String>,
    /// A directory of `.zone` files.
    #[arg(long)]
    zone_dir: Option<String>,
    /// Who may request a zone transfer: an address or CIDR prefix, repeatable.
    ///
    /// Nobody, unless this says otherwise. An AXFR is the whole zone in one
    /// answer, so it is the one query that has to be allowed by list. Applies to
    /// TCP, because AXFR is defined over TCP alone (RFC 5936 §4.2).
    #[arg(long, value_name = "ADDR|CIDR")]
    allow_transfer: Vec<String>,
    /// A TSIG key, `[algorithm:]name:base64secret`, repeatable.
    ///
    /// Holding the key is an identity; coming from an address is not. A request
    /// signed with a key named here may transfer a zone whatever its source
    /// address, and any signed request gets a signed answer (RFC 8945). The
    /// algorithm defaults to hmac-sha256.
    #[arg(long, value_name = "[ALG:]NAME:SECRET")]
    tsig_key: Vec<String>,
    /// A secondary to notify when a zone changes: `addr[:port]`, repeatable.
    ///
    /// Without this a secondary hears about a change when its refresh timer next
    /// goes off, which for a typical SOA is hours later. A NOTIFY says so at once
    /// (RFC 1996). Sent on zone load — at startup and on SIGHUP — for every zone
    /// whose serial moved forward.
    #[arg(long, value_name = "ADDR[:PORT]")]
    also_notify: Vec<String>,
    /// A zone to replicate: `zone@master[:port][#tsig-key-name]`, repeatable.
    ///
    /// Makes this server a *secondary* for that zone: it asks the master for the
    /// SOA on the zone's own REFRESH timer, transfers when the serial has moved,
    /// and stops serving the zone entirely once EXPIRE has passed without
    /// contact. Repeat with the same zone to give it more than one master.
    ///
    /// Requires `--zone-dir`, because a fetched zone has to be written somewhere:
    /// the file lands there under the zone's name and is loaded by the ordinary
    /// path on the next start.
    #[arg(long, value_name = "ZONE@MASTER[:PORT][#KEY]")]
    secondary: Vec<String>,
    /// A directory of `.rdnskey` signing keys.
    ///
    /// Every zone this server loads from disk whose apex matches a key here is
    /// signed in memory as it loads: the DNSKEY RRset published, every
    /// authoritative RRset signed, and an NSEC chain generated. The zone file
    /// itself is never rewritten — what a client validates is what leaves the
    /// socket, and a resigning timer racing an editor for one file is a way to
    /// lose a zone. Zones with no key here are served exactly as before.
    #[arg(long, value_name = "DIR")]
    signing_key_dir: Option<PathBuf>,
    /// How long a generated signature is good for, in days.
    ///
    /// Signatures are made at load — startup, and SIGHUP where signals exist —
    /// so this also says how often the zone has to be reloaded. It is long by
    /// default for that reason.
    #[arg(long, value_name = "DAYS", default_value = "30")]
    signature_validity: u32,
    /// Deny names with NSEC3 (RFC 5155) rather than NSEC.
    ///
    /// With no salt and no extra iterations, which is what RFC 9276 §3.1 asks
    /// for: both were meant to cost an attacker something and only ever cost
    /// the server and the validator. The reason left to choose NSEC3 is that
    /// NSEC lets anyone walk the zone one query at a time.
    #[arg(long)]
    nsec3: bool,
    /// Leave insecure delegations out of the NSEC3 chain (RFC 5155 §6).
    ///
    /// For a zone with many unsigned children, which would otherwise pay a
    /// record and a signature each. The cost is that a denial covering an
    /// opted-out span proves less: "not here, or an insecure delegation I did
    /// not list".
    #[arg(long, requires = "nsec3")]
    nsec3_opt_out: bool,
    /// Generate a key-signing and a zone-signing key for ZONE, print the DS
    /// record to give the parent, and exit.
    ///
    /// Writes both into `--signing-key-dir`, which must exist. Nothing is
    /// served in this mode: it is the one thing that has to happen before a
    /// zone can be signed, and it happens once.
    #[arg(long, value_name = "ZONE", requires = "signing_key_dir")]
    generate_keys: Option<String>,
    /// The algorithm `--generate-keys` uses: a number or a mnemonic.
    #[arg(long, value_name = "ALG", default_value = "ECDSAP256SHA256")]
    key_algorithm: String,
    /// Refuse to serve a zone that is not signed, or whose signatures do not
    /// verify.
    ///
    /// Off by default, which is the only sane default for a server that may
    /// hold a mix: most zones are unsigned and serving them is the normal case.
    /// Turning it on is an operator assertion that every zone here is meant to
    /// be signed — worth making, because a zone that silently loses its
    /// signatures otherwise keeps answering as though nothing happened.
    #[arg(long)]
    require_signed: bool,
    /// Serve the zones that loaded even if others in --zone-dir failed to parse.
    ///
    /// Off by default, and the default is the safe one. A zone file that fails to
    /// parse used to be skipped with one line on stderr: the process stayed up,
    /// exit code 0, and that zone answered REFUSED — indistinguishable from a
    /// zone nobody configured. One typo in 1 of 40 zones plus a deploy SIGHUP is
    /// a lame delegation for that zone, 39 green dashboards, and a log line that
    /// scrolled past hours ago.
    ///
    /// The flag exists because the behaviour is defensible when the alternative
    /// is worse — a secondary holding 40 zones would rather serve 39 than none —
    /// but it should be a decision, not what happens when nobody looked.
    #[arg(long)]
    allow_partial_load: bool,
    /// Response bytes per second, per client address. 0 turns the budget off.
    ///
    /// Meters what leaves rather than what arrives, because that is what an
    /// amplification attack is made of. Applies to UDP: a TCP query has completed
    /// a handshake, so there is nobody to reflect at.
    #[arg(long, value_name = "BYTES_PER_SEC", default_value = "8192")]
    response_rate: u32,
}

/// Zone source: either a single file or a directory of zone files
#[derive(Clone)]
enum ZoneSource {
    SingleFile(String),
    Directory(String),
}

/// Build a DNS response for the given query message
/// 
/// Looks up the zone based on the query name and returns appropriate response
fn make_response(
    msg: &DnsMessage,
    zone_map: &HashMap<String, Zone>,
    metrics: &DnsMetrics,
) -> DnsMessage {
    let timer = LatencyTimer::new();
    let mut response = DnsMessage {
        id: msg.id,
        response: true,
        opcode: msg.opcode,
        authoritive: true,
        truncation: false,
        recursion: msg.recursion,
        recursion_ok: false,
        ad: false,
        cd: msg.cd,
        rcode: ResponseCode::Ok,
        queries: msg.queries.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    // EDNS-level rejections take precedence over any zone lookup: a malformed
    // option list is FORMERR, and an EDNS version we don't implement is BADVERS
    // (RFC 6891 §6.1.3). Both replies carry a bare version-0 OPT — BADVERS is an
    // extended RCODE, so the OPT record is what carries its high bits.
    let edns_rejection = match msg.edns() {
        Err(_) => Some(ResponseCode::FormatError),
        Ok(Some(edns)) if edns.version > EDNS_VERSION => Some(ResponseCode::BadOptVersion),
        _ => None,
    };
    if let Some(rcode) = edns_rejection {
        response.rcode = rcode;
        // `with_payload_size` carries no options, so encoding it cannot fail.
        let _ = response.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
        return response;
    }

    // DO says the client can make sense of DNSSEC records, so send them
    // (RFC 4035 §3.1.1). It is not a request for validation and not a demand
    // that the zone be signed — an unsigned zone answers a DO query exactly as
    // it answers any other, and [`dnssec_answer`] returns nothing for it.
    let dnssec_ok = matches!(msg.edns(), Ok(Some(edns)) if edns.do_bit);

    // Only QUERY reaches the zone lookup. NOTIFY is answered by the caller,
    // which knows the peer's address; anything else — UPDATE, STATUS, the
    // obsolete IQUERY — is something this server does not implement, and saying
    // so is more useful than treating it as a lookup (RFC 1035 §4.1.1).
    if msg.opcode != OpCode::Query {
        response.rcode = ResponseCode::NotImplemented;
        response.authoritive = false;
        return response;
    }

    // Process each query
    for query in &msg.queries {
        // A transfer over UDP is not a transfer. AXFR is defined over TCP alone
        // (RFC 5936 §4.2) — a whole zone does not fit a datagram and the protocol
        // has no way to say "there is more" — so a UDP request for it is
        // malformed rather than merely refused. The TCP server answers AXFR
        // itself, before ever reaching here, so this is the UDP path speaking.
        if query.qtype == record_types::AXFR {
            response.rcode = ResponseCode::FormatError;
            continue;
        }

        // An IXFR over UDP is different: it is *expected*, and RFC 1995 §2 gives
        // the answer for one that will not fit in a datagram — a single SOA of
        // the server's current version, which tells the client to come back over
        // TCP. Answering that way always is a deliberate choice rather than a
        // limitation: the ACL, the TSIG session and the multi-message packing all
        // live on the TCP path, and duplicating them here to serve the small
        // subset of increments that fit a datagram would be a second
        // implementation of the interesting parts. The SOA discloses nothing an
        // ordinary SOA query does not, so it needs no ACL of its own.
        if query.qtype == record_types::IXFR {
            if let Some(zone) = find_zone_for_query(&query.qname, zone_map) {
                for soa in zone.query(zone.origin(), record_types::SOA) {
                    response.answers.push(ResourceRecord {
                        name: zone.origin().to_string(),
                        class: soa.class,
                        ttl: soa.ttl,
                        rdata: soa.rdata.clone(),
                    });
                }
            } else {
                response.rcode = ResponseCode::Refused;
                response.authoritive = false;
            }
            continue;
        }

        // Find the matching zone for this query
        let zone = find_zone_for_query(&query.qname, zone_map);

        if let Some(zone) = zone {
            match resolve_in_zone(zone, &query.qname, query.qtype) {
                Outcome::Referral { cut } => {
                    refer_to_child(zone, &cut, dnssec_ok, &mut response);
                    metrics.increment_cache_misses();
                }
                Outcome::Answer { chain, name } => {
                    add_chain(zone, &chain, dnssec_ok, &mut response);
                    add_answer(zone, &name, query.qtype, dnssec_ok, &mut response);
                    metrics.increment_cache_hits();
                }
                Outcome::Negative { chain, name, kind } => {
                    add_chain(zone, &chain, dnssec_ok, &mut response);
                    add_negative(zone, &name, &kind, dnssec_ok, &mut response);
                    metrics.increment_cache_misses();
                }
                Outcome::ChainLeftZone { chain } => {
                    add_chain(zone, &chain, dnssec_ok, &mut response);
                    metrics.increment_cache_hits();
                }
            }

            metrics.increment_query_counter();
        } else {
            // A zone we do not serve is REFUSED, not NXDOMAIN, and the two are
            // not interchangeable. NXDOMAIN is an assertion *about the DNS* —
            // this name does not exist anywhere — which we have no standing to
            // make about a zone we hold nothing for; a resolver believes it and
            // caches it (RFC 2308), so the lie propagates. REFUSED says the
            // truth, that this server will not answer, and sends the resolver to
            // the other nameservers in the delegation. It is what BIND, NSD and
            // Knot all answer here.
            //
            // This matters more now that a zone can be *withdrawn*: an expired
            // secondary that answered NXDOMAIN would take its zone off the
            // internet for as long as anything cached the answer, which is the
            // opposite of what stopping serving it is for.
            response.rcode = ResponseCode::Refused;
            response.authoritive = false;
            metrics.increment_cache_misses();
        }
    }

    // Log query response with latency
    let query_name = msg
        .queries
        .first()
        .map(|q| q.qname.as_str())
        .unwrap_or("unknown");
    let query_type = msg.queries.first().map(|q| q.qtype).unwrap_or(0);
    instrumentation::trace_query_response(query_name, query_type, timer.elapsed_ms(), None);

    // Mirror EDNS0: only include an OPT record when the client used EDNS
    // (RFC 6891 §6.1.1), advertising our own UDP payload size. DO is echoed
    // when it was asked for, which is how the client knows the DNSSEC records
    // it did or did not get were a deliberate answer (RFC 3225 §3).
    if msg.has_edns() {
        let mut edns = Edns::with_payload_size(RDNSD_PAYLOAD_SIZE);
        edns.do_bit = dnssec_ok;
        let _ = response.set_edns(edns);
    }

    response
}

/// What RFC 1034 §4.3.2 decided about one question against one zone.
///
/// The algorithm there is a loop with four exits, and only two of them were ever
/// implemented here: records, or a negative answer. The two that were missing are
/// the ones an ordinary zone cannot be served without — a referral at a
/// delegation, and following an alias.
enum Outcome {
    /// The zone's authority stops at `cut`: the answer is a referral to the
    /// child, with AA **clear** (RFC 1035 §4.1.1).
    Referral { cut: String },
    /// There are records for the question at `name`, reached through the
    /// aliases at `chain` (empty in the ordinary case).
    Answer { chain: Vec<String>, name: String },
    /// No records. `name` is the name the "no" is about — the end of the chain
    /// when one was followed — and `kind` decides NXDOMAIN against NODATA.
    Negative {
        chain: Vec<String>,
        name: String,
        kind: NameKind,
    },
    /// The chain walked out of this zone: NOERROR with the aliases we do hold
    /// and nothing else. **Not** NXDOMAIN — we know nothing about the target,
    /// and saying it does not exist would take it off the internet for as long
    /// as anything cached the answer (RFC 1034 §4.3.2 step 3a).
    ChainLeftZone { chain: Vec<String> },
}

/// How many aliases we will follow inside one zone before giving up.
///
/// A zone with `a CNAME b` and `b CNAME a` is a broken zone, not an attack, but
/// the loop is real and the visited set below is what actually stops it. This is
/// the second bound, for the chain that grows without repeating.
const MAX_CNAME_HOPS: usize = 16;

/// Walk RFC 1034 §4.3.2 for one question.
///
/// The four cases are tried in this order at every name, which is the order the
/// RFC gives and the order that matters: the zone's authority ends here, the
/// name has the data, the name is an alias, the name has no such data. Getting
/// the first one last is how a parent ends up answering NXDOMAIN for a child's
/// names.
fn resolve_in_zone(zone: &Zone, qname: &str, qtype: u16) -> Outcome {
    let mut chain: Vec<String> = Vec::new();
    let mut visited: Vec<String> = Vec::new();
    let mut name = qname.to_string();

    for _ in 0..MAX_CNAME_HOPS {
        // A delegation is a referral whatever the type asked for, with one
        // exception: the DS *at* the cut is the parent's own statement about the
        // child, so it is answered here rather than sent downwards — the child
        // does not hold its own DS and could not be asked (RFC 4035 §3.1.4.1).
        if let Some(cut) = zone.delegation_for(&name) {
            let at_the_cut = cut.eq_ignore_ascii_case(&zone.normalize_name(&name));
            if !(qtype == record_types::DS && at_the_cut) {
                return if chain.is_empty() {
                    Outcome::Referral { cut }
                } else {
                    // Mid-chain, the target is the child's name to answer for.
                    // Stopping with what we hold costs the resolver one round
                    // trip and cannot be wrong; answering from the glue below
                    // the cut would serve occluded data as authoritative.
                    Outcome::ChainLeftZone { chain }
                };
            }
        }

        let kind = zone.name_kind(&name);
        if !zone.query(&name, qtype).is_empty() {
            return Outcome::Answer { chain, name };
        }
        // A CNAME query is answered by the CNAME, not followed by it — the
        // alias is the data when the alias is what was asked for.
        if qtype == record_types::CNAME {
            return Outcome::Negative { chain, name, kind };
        }

        let Some(target) = cname_target(zone, &name) else {
            return Outcome::Negative { chain, name, kind };
        };
        chain.push(name.clone());
        visited.push(zone.normalize_name(&name).to_ascii_lowercase());

        let target_key = zone.normalize_name(&target).to_ascii_lowercase();
        if !in_zone(zone, &target_key) || visited.contains(&target_key) {
            return Outcome::ChainLeftZone { chain };
        }
        name = target;
    }
    Outcome::ChainLeftZone { chain }
}

/// The target of the CNAME at `name`, if there is one.
///
/// Only the first is read. RFC 1034 §3.6.2 allows exactly one CNAME at an owner
/// name — a second is a broken zone, and picking one arbitrarily is better than
/// answering with a two-record RRset no client can use. The parser refuses to
/// load the shape at all (see `zone::parse_zone_file`), so this is the belt to
/// that braces.
fn cname_target(zone: &Zone, name: &str) -> Option<String> {
    zone.query(name, record_types::CNAME)
        .first()
        .and_then(|record| match record.rdata.parse() {
            Ok(rdns::ParsedRecord::CNAME(target)) => Some(target),
            _ => None,
        })
}

/// Whether an absolute, down-cased name is at or below this zone's apex.
fn in_zone(zone: &Zone, name: &str) -> bool {
    let origin = zone.origin().to_ascii_lowercase();
    name == origin
        || (name.len() > origin.len()
            && name.ends_with(&origin)
            && name.as_bytes()[name.len() - origin.len() - 1] == b'.')
}

/// Put the records of `qtype` at `name` into the answer section, with their
/// signatures.
///
/// The answer echoes the name asked about rather than the stored owner, which
/// may be `@`, relative, or a wildcard — and for a wildcard match the queried
/// name is what the client must see (RFC 1034 §4.3.3).
fn add_answer(
    zone: &Zone,
    name: &str,
    qtype: u16,
    dnssec_ok: bool,
    response: &mut DnsMessage,
) {
    for record in zone.query(name, qtype) {
        response.answers.push(ResourceRecord {
            name: name.to_string(),
            class: record.class,
            ttl: record.ttl,
            rdata: record.rdata.clone(),
        });
    }

    if dnssec_ok {
        let signatures = dnssec_answer::answer_signatures(zone, name, qtype);
        // A wildcard answer is not finished when its signature is attached. The
        // same signature verifies at every name that wildcard reaches, so the
        // answer also has to say that the name actually asked for is not in the
        // zone (RFC 4035 §3.1.3) — otherwise one captured answer is a valid
        // answer for all of them.
        if signatures.wildcard.is_some() {
            response
                .authorities
                .extend(dnssec_answer::proof_of_absence(zone, name));
        }
        response.answers.extend(signatures.records);
    }
}

/// The aliases walked to reach the answer, in the order they were followed.
///
/// Each is a CNAME RRset at its own owner name, so it carries its own signature
/// — and its own wildcard denial when the alias was synthesized.
fn add_chain(zone: &Zone, chain: &[String], dnssec_ok: bool, response: &mut DnsMessage) {
    for at in chain {
        add_answer(zone, at, record_types::CNAME, dnssec_ok, response);
    }
}

/// A negative answer: the rcode, the SOA that says how long it may be cached,
/// and the proof of it when the client can check one.
fn add_negative(
    zone: &Zone,
    name: &str,
    kind: &NameKind,
    dnssec_ok: bool,
    response: &mut DnsMessage,
) {
    if matches!(kind, NameKind::NotFound) {
        response.rcode = ResponseCode::NoSuchDomain;
    }

    // Both kinds of "no" carry the zone's SOA in the authority section
    // (RFC 2308 §2.1 and §2.2). It is not decoration: it is what tells the
    // client, and every resolver in between, how long the answer may be cached.
    // Without it a negative answer is uncacheable, so each repeat of a failing
    // lookup comes back to us.
    for soa in zone.query(zone.origin(), record_types::SOA) {
        response.authorities.push(ResourceRecord {
            name: zone.origin().to_string(),
            class: soa.class,
            ttl: negative_ttl(soa),
            rdata: soa.rdata.clone(),
        });
    }

    // An unsigned "no" is a "no" a resolver has to take on trust, which for a
    // signed zone is the one thing DNSSEC exists to avoid: the proof is what
    // stops a forged NXDOMAIN taking a name off the internet for as long as it
    // stays cached.
    if dnssec_ok {
        response
            .authorities
            .extend(dnssec_answer::negative_proof(zone, name, kind));
    }
}

/// How long a negative answer may be cached: `min(SOA MINIMUM, the SOA record's
/// own TTL)` (RFC 2308 §3).
///
/// The record's own TTL alone is wrong, and wrong in the expensive direction.
/// For the zone shape this repo's own tests use — `$TTL 3600`, `minimum 300` —
/// sending it verbatim advertises every NXDOMAIN and NODATA at 3600 where the
/// RFC says 300, so a record added to fix a typo takes an hour to appear instead
/// of five minutes. It was also internally inconsistent: the signer already caps
/// the NSEC/NSEC3 TTL at MINIMUM (`zone_signer::sign_zone`), so the SOA and the
/// proof beside it in the same section disagreed about how long the "no" was
/// good for.
fn negative_ttl(soa: &rdns::zone::ZoneRecord) -> i32 {
    match soa.rdata.parse() {
        Ok(rdns::ParsedRecord::SOA { minimum, .. }) => {
            soa.ttl.min(minimum.min(i32::MAX as u32) as i32)
        }
        // An apex SOA that will not parse is a zone that should not have loaded.
        // Capping at nothing is the conservative direction: the client asks
        // again rather than caching a "no" we cannot bound.
        _ => 0,
    }
}

/// A referral to the child zone: the delegation's NS RRset, its glue, and — for
/// a client that can check it — the DS or the proof there is none.
///
/// AA is **clear**, which is the whole point. This server hardcoded it true and
/// answered NXDOMAIN for names below a delegation, so per RFC 8020 every
/// resolver cached "the entire subtree does not exist" and the child zone went
/// off the internet for the negative TTL.
fn refer_to_child(zone: &Zone, cut: &str, dnssec_ok: bool, response: &mut DnsMessage) {
    response.authoritive = false;

    let mut targets: Vec<String> = Vec::new();
    for ns in zone.query(cut, record_types::NS) {
        if let Ok(rdns::ParsedRecord::NS(target)) = ns.rdata.parse() {
            targets.push(target);
        }
        response.authorities.push(ResourceRecord {
            name: cut.to_string(),
            class: ns.class,
            ttl: ns.ttl,
            rdata: ns.rdata.clone(),
        });
    }

    // Glue, and only in-bailiwick glue: an address we hold for a nameserver
    // under this zone is a hint we are entitled to give, while one for a name in
    // somebody else's zone is an assertion about their data. A resolver worth
    // anything discards the latter, and sending it is how cache-poisoning
    // attempts look (RFC 1034 §4.2.1).
    for target in targets {
        let key = zone.normalize_name(&target).to_ascii_lowercase();
        if !in_zone(zone, &key) {
            continue;
        }
        for rtype in [record_types::A, record_types::AAAA] {
            for glue in zone.query(&target, rtype) {
                response.additionals.push(ResourceRecord {
                    name: target.clone(),
                    class: glue.class,
                    ttl: glue.ttl,
                    rdata: glue.rdata.clone(),
                });
            }
        }
    }

    if dnssec_ok {
        response
            .authorities
            .extend(dnssec_answer::delegation_proof(zone, cut));
    }
}

/// Find the zone that should handle this query
///
/// Matches the query name against zone origins, preferring the most specific (longest) match
fn find_zone_for_query<'a>(qname: &str, zone_map: &'a HashMap<String, Zone>) -> Option<&'a Zone> {
    // Wire-format query names are absolute ("www.example.com."), so the trailing
    // dot has to come off both sides before comparing — otherwise nothing ever
    // matches an origin and every query is an NXDOMAIN.
    let qname_lower = qname.to_lowercase();
    let qname_lower = qname_lower.trim_end_matches('.');

    // Find all zones that could handle this query
    let mut candidates: Vec<_> = zone_map
        .values()
        .filter(|zone| {
            let zone_origin = zone.origin().trim_end_matches('.').to_lowercase();
            // The root zone serves everything; otherwise the query must be the
            // origin or sit under it *at a label boundary*, so that a zone for
            // "example.com" doesn't capture "notexample.com".
            zone_origin.is_empty()
                || qname_lower == zone_origin
                || qname_lower
                    .strip_suffix(&zone_origin)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
        .collect();
    
    // Sort by zone origin length (longest first, most specific)
    candidates.sort_by(|a, b| {
        b.origin().len().cmp(&a.origin().len())
    });
    
    candidates.first().copied()
}

/// Everything both transports answer from. One of these per process, so a
/// connection task or a datagram task clones a single `Arc`.
///
/// Shared deliberately. A client's rate limit should not reset because it switched
/// transport, and the metrics are one server's, not one socket's — with a process
/// per transport they were two sets that each saw half the traffic.
struct Server {
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    rate_limiter: Arc<RateLimiter>,
    validator: Arc<RequestValidator>,
    logger: Arc<QueryLogger>,
    metrics: Arc<DnsMetrics>,
    /// Who may ask for a zone transfer. Empty by default, which refuses everyone.
    transfer_acl: Arc<TransferAcl>,
    /// The TSIG keys we know. Holding one is an identity; an address is not.
    tsig_keys: Arc<TsigKeyring>,
    /// Bytes-per-second budget for UDP replies. Not applied to TCP: a query that
    /// completed a handshake has an address nobody can be reflecting at.
    response_limiter: Arc<ResponseLimiter>,
    /// The zones we replicate, so a NOTIFY can be told from a plausible one.
    secondaries: Secondaries,
    /// What changed between the versions of each zone we have held, so an IXFR
    /// can answer with the difference rather than the whole zone. Derived from
    /// the zone map, so the two are only ever updated together.
    deltas: Arc<RwLock<DeltaLog>>,
}

/// Bind both transports and serve them from one process.
async fn serve(
    addr: &str,
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    transfer_acl: TransferAcl,
    tsig_keys: TsigKeyring,
    response_rate: u32,
    secondaries: Secondaries,
    deltas: Arc<RwLock<DeltaLog>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let transfers = if transfer_acl.is_empty() && tsig_keys.is_empty() {
        "refused (no --allow-transfer, no --tsig-key)".to_string()
    } else {
        format!(
            "allowed for {} address rule(s) and {} key(s)",
            transfer_acl.len(),
            tsig_keys.len()
        )
    };
    let budget = if response_rate == 0 {
        "off".to_string()
    } else {
        format!("{response_rate} bytes/s per client")
    };

    // Bind both before announcing anything, so a port conflict fails here rather
    // than after one transport is already up.
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    let listener = TcpListener::bind(addr).await?;

    let server = Arc::new(Server {
        zone_map,
        rate_limiter: Arc::new(RateLimiter::with_defaults()),
        validator: Arc::new(RequestValidator::with_defaults()),
        logger: Arc::new(QueryLogger::new()),
        metrics: Arc::new(DnsMetrics::new()),
        transfer_acl: Arc::new(transfer_acl),
        tsig_keys: Arc::new(tsig_keys),
        response_limiter: Arc::new(if response_rate == 0 {
            ResponseLimiter::disabled()
        } else {
            ResponseLimiter::new(response_rate, response_rate.saturating_mul(4), 2)
        }),
        secondaries,
        deltas,
    });
    println!(
        "rdnsd listening on {addr} (UDP+TCP), zone transfer: {transfers}, \
         response budget: {budget}, TSIG keys: {}",
        server.tsig_keys.len()
    );

    let udp = tokio::spawn(udp_loop(socket, server.clone()));
    let tcp = tokio::spawn(tcp_loop(listener, server));

    // Neither loop returns in normal operation. Whichever fails first takes the
    // process down rather than leaving us serving one transport and not the other.
    tokio::select! {
        r = udp => r??,
        r = tcp => r??,
    }
    Ok(())
}

/// Accept connections and serve each in its own task.
async fn tcp_loop(listener: TcpListener, server: Arc<Server>) -> Result<(), std::io::Error> {
    let permits = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = listener.accept().await?;
        // Back-pressure on accept: at the ceiling we simply stop taking new
        // connections until one finishes, rather than spawning unboundedly.
        // The semaphore is never closed, so this only fails if we drop it.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            continue;
        };
        let server = server.clone();
        tokio::spawn(async move {
            server.serve_connection(stream, peer).await;
            drop(permit);
        });
    }
}

impl Server {
    /// Serve one connection until it goes idle, closes, or misbehaves.
    ///
    /// A connection carries any number of queries (RFC 7766 §6.2.1), and they
    /// are answered **concurrently**: reading, answering and writing are three
    /// separate jobs, so one slow query cannot stall the queries behind it
    /// (§6.2.1.1).
    async fn serve_connection(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) {
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_INFLIGHT_PER_CONNECTION);

        // One task owns the write half. Answers may complete out of order —
        // RFC 7766 §6.2.1.1 allows that, and clients match on the transaction
        // id — but two framed messages must never interleave on the wire, so
        // every reply funnels through here.
        let writer_logger = self.logger.clone();
        let writer_task = tokio::spawn(async move {
            while let Some(framed) = rx.recv().await {
                if let Err(e) = writer.write_all(&framed).await {
                    writer_logger.log_error(peer.ip(), &format!("socket write error: {}", e));
                    break;
                }
            }
        });

        let in_flight = Arc::new(Semaphore::new(MAX_INFLIGHT_PER_CONNECTION));

        loop {
            // DNS over TCP frames every message with a 2-byte big-endian length
            // prefix (RFC 1035 §4.2.2). Read the prefix first, then exactly that
            // many bytes — a single `read` can return a short or coalesced chunk.
            //
            // Between messages the peer may legitimately be idle, so a timeout
            // here (like EOF) is an ordinary end to a connection, not an error.
            let mut len_buf = [0u8; 2];
            match tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                _ => break,
            }

            let len = u16::from_be_bytes(len_buf) as usize;
            if len == 0 {
                self.logger.log_error(peer.ip(), "zero-length TCP message");
                break;
            }

            // Mid-message the peer has committed to sending `len` bytes, so a
            // stall here gets a much shorter leash than an idle connection.
            let mut packet = vec![0u8; len];
            match tokio::time::timeout(TCP_READ_TIMEOUT, reader.read_exact(&mut packet)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    self.logger
                        .log_error(peer.ip(), &format!("socket read error: {}", e));
                    break;
                }
                Err(_) => {
                    self.logger
                        .log_error(peer.ip(), "timed out mid-message on TCP");
                    break;
                }
            }

            // Cap in-flight work per connection: this await is what stops a
            // pipelining client from spawning tasks faster than we retire them.
            let Ok(permit) = in_flight.clone().acquire_owned().await else {
                break;
            };
            let server = self.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                // A reply is a sequence, because a zone transfer is: several
                // messages that must reach the wire in the order they were built.
                // One sender keeps that order; another query's reply may land
                // between them, which is legal — a client demultiplexes on the
                // transaction id.
                for framed in server.answer(&packet, peer).await {
                    // A send error means the writer is gone (the peer hung up);
                    // there is nowhere left to put the rest.
                    if tx.send(framed).await.is_err() {
                        break;
                    }
                }
                drop(permit);
            });
        }

        // Dropping our sender lets the writer drain the replies still in flight
        // — the clones held by running tasks keep the channel open — and then
        // exit on its own.
        drop(tx);
        let _ = writer_task.await;
    }

    /// Answer one query, returning the length-prefixed messages to write back.
    ///
    /// A list rather than one message, because an AXFR response is a sequence
    /// (RFC 5936 §2.2). Empty means the query earned no response at all.
    async fn answer(&self, packet: &[u8], peer: SocketAddr) -> Vec<Vec<u8>> {
        let ip = peer.ip();

        if !self.rate_limiter.should_allow(ip) {
            self.logger.log_rate_limited(ip);
            instrumentation::trace_rate_limit_check(&ip, false);
            return Vec::new();
        }
        instrumentation::trace_rate_limit_check(&ip, true);

        let validation = self.validator.validate_packet(packet, true);
        if !validation.is_valid() {
            self.logger.log_error(
                ip,
                &format!(
                    "invalid query: {}",
                    validation.error_message().unwrap_or("unknown error")
                ),
            );
            instrumentation::trace_validation(&ip, false, validation.error_message());
            return Vec::new();
        }
        instrumentation::trace_validation(&ip, true, None);

        let Ok(msg) = DnsMessage::try_from_bytes(packet) else {
            self.logger.log_error(ip, "failed to parse DNS message");
            return Vec::new();
        };

        // A response is not a question. `RequestValidator` deliberately accepts
        // QR=1 — it is used on both directions of the wire and a response
        // legitimately carries answers — so the check belongs here, where we know
        // this packet arrived at a listening socket. Answering one turns a pair
        // of servers, or one spoofed datagram, into a packet loop; and there is
        // no reply to send, because the sender did not ask anything.
        if msg.response {
            self.logger
                .log_error(ip, "a response was sent to a server port; dropped");
            return Vec::new();
        }

        let qtype = msg.queries.first().map(|q| q.qtype);
        self.logger.log_query(ip, qtype);
        let query_name = msg
            .queries
            .first()
            .map(|q| q.qname.as_str())
            .unwrap_or("unknown");
        instrumentation::trace_query_received(&ip, query_name, qtype.unwrap_or(0));

        // TSIG before anything else that could answer: a signed message is
        // either authentic or it is not, and a server that answered the question
        // first and checked the signature afterwards would be answering questions
        // for whoever asked (RFC 8945 §5.2).
        let now = tsig::now();
        let mut session = match tsig::check_request(packet, &self.tsig_keys, now) {
            TsigCheck::Unsigned => None,
            TsigCheck::Verified(session) => Some(session),
            TsigCheck::Rejected(rejection) => {
                self.logger.log_error(
                    ip,
                    &format!(
                        "TSIG rejected (key {}): {}",
                        rejection.key_name(),
                        rejection.error.reason()
                    ),
                );
                let response = match self.error_bytes(&msg, ResponseCode::NotAuthorized) {
                    Some(bytes) => bytes,
                    None => return Vec::new(),
                };
                return match rejection.attach(response, now) {
                    Ok(bytes) => vec![frame(&bytes)],
                    Err(e) => {
                        self.logger.log_error(ip, &format!("TSIG error reply: {e}"));
                        Vec::new()
                    }
                };
            }
        };

        // A transfer is answered here rather than in `make_response`: it is a
        // sequence of messages, it is gated on an ACL, and it is the only kind of
        // query whose answer can be the entire zone.
        if matches!(
            msg.queries.first().map(|q| q.qtype),
            Some(record_types::AXFR) | Some(record_types::IXFR)
        ) {
            return self.answer_transfer(&msg, peer, session.as_mut(), now).await;
        }

        // Hold the zone lock only as long as it takes to build and serialize the
        // response — never across a socket write, or a SIGHUP zone reload would
        // queue behind a slow client for the life of its connection.
        let bytes = {
            let zones = self.zone_map.read().await;
            let resp = if msg.opcode == OpCode::Notify {
                notify_reply(&msg, &zones, &self.secondaries, peer)
            } else {
                make_response(&msg, &zones, &self.metrics)
            };
            // Over TCP the 2-byte length prefix is the only size limit, so the
            // EDNS UDP payload size does not apply (RFC 6891 §6.2.2).
            match resp.to_bytes_within(u16::MAX as usize) {
                Ok(bytes) => bytes,
                Err(e) => {
                    self.logger
                        .log_error(ip, &format!("serialization error: {}", e));
                    return Vec::new();
                }
            }
        };

        // A signed question earns a signed answer, and it is the same session,
        // so the reply's MAC covers the request's — which is what stops a reply
        // to one question being replayed as the reply to another.
        match session.as_mut() {
            Some(session) => match session.sign(bytes, now) {
                Ok(signed) => vec![frame(&signed)],
                Err(e) => {
                    self.logger.log_error(ip, &format!("TSIG signing failed: {e}"));
                    Vec::new()
                }
            },
            None => vec![frame(&bytes)],
        }
    }

    /// Answer an AXFR: the whole zone, or a refusal.
    ///
    /// Every attempt is logged, allowed or not. This is the one request where
    /// knowing it happened matters as much as whether it was permitted — a
    /// refused one is a probe, and an allowed one is a copy of the zone leaving
    /// the building.
    async fn answer_transfer(
        &self,
        msg: &DnsMessage,
        peer: SocketAddr,
        mut session: Option<&mut TsigSession>,
        now: u64,
    ) -> Vec<Vec<u8>> {
        let ip = peer.ip();
        let qname = msg
            .queries
            .first()
            .map(|q| q.qname.clone())
            .unwrap_or_default();
        let incremental = msg.queries.first().map(|q| q.qtype) == Some(record_types::IXFR);
        let kind = if incremental { "IXFR" } else { "AXFR" };

        // Two ways to be allowed, and they are not equivalent. A verified TSIG is
        // proof that the peer holds a secret we gave it; an address is a claim the
        // network makes on its behalf. Either grants the transfer, and which one
        // did is worth writing down.
        //
        // An IXFR is gated identically, and for the identical reason: it may
        // *answer* with the whole zone (RFC 1995 §4), so a policy that let it
        // through would be no policy at all.
        let authenticated_by = session.as_ref().map(|s| s.key_name().to_string());
        if authenticated_by.is_none() && !self.transfer_acl.allows(ip) {
            self.logger.log_error(
                ip,
                &format!("{kind} of {qname} refused: {ip} has no key and is not in --allow-transfer"),
            );
            println!("{kind} of {qname} from {ip}: REFUSED (no TSIG key, not in --allow-transfer)");
            return self.transfer_error(msg, ResponseCode::Refused, ip);
        }

        // A transfer names a zone apex, not any name within it: transferring
        // example.com. because www.example.com. was asked for would hand over a
        // zone nobody named. So this is an exact match on the origin, not the
        // enclosing-zone lookup an ordinary query does.
        let messages = {
            let zones = self.zone_map.read().await;
            let apex = absolute_name(&qname);
            let Some(zone) = zones.values().find(|z| z.origin().eq_ignore_ascii_case(&apex)) else {
                println!("{kind} of {qname} from {ip}: NOTAUTH (not a zone served here)");
                return self.transfer_error(msg, ResponseCode::NotAuthorized, ip);
            };
            let built = if incremental {
                // The delta log is read under the zone lock, so the increments
                // and the zone they are increments *of* are the same version.
                // Taken separately, a reload between the two reads would produce
                // a chain that does not match the SOA framing it is wrapped in.
                let deltas = self.deltas.read().await;
                ixfr_response(msg, zone, &deltas).map(|response| {
                    match &response {
                        IxfrResponse::UpToDate(_) => {
                            println!("IXFR of {qname} from {ip}: already current, sending one SOA")
                        }
                        IxfrResponse::Incremental { steps, records, .. } => println!(
                            "IXFR of {qname} to {ip}: {records} record(s) across {steps} version(s)"
                        ),
                        IxfrResponse::FullTransfer { why, .. } => println!(
                            "IXFR of {qname} to {ip}: sending the whole zone instead ({why})"
                        ),
                    }
                    response.messages()
                })
            } else {
                axfr_messages(msg, zone)
            };
            match built {
                Ok(messages) => messages,
                Err(e) => {
                    self.logger.log_error(ip, &format!("{kind} of {qname}: {e}"));
                    return self.transfer_error(msg, ResponseCode::ServerFailure, ip);
                }
            }
        };

        let mut frames = Vec::with_capacity(messages.len());
        let mut records = 0;
        for message in &messages {
            records += message.answers.len();
            let bytes = match message.to_bytes_within(u16::MAX as usize) {
                Ok(bytes) => bytes,
                Err(e) => {
                    // Half a transfer is worse than none: the client cannot tell
                    // a stream that stopped early from one that finished, so give
                    // up on the whole thing rather than send a prefix of it.
                    self.logger
                        .log_error(ip, &format!("{kind} of {qname}: serialization error: {e}"));
                    return self.transfer_error(msg, ResponseCode::ServerFailure, ip);
                }
            };
            // Every envelope is signed, and the MACs chain (RFC 8945 §5.3.1): a
            // dropped or reordered message then fails at the client instead of
            // passing for a complete zone.
            let bytes = match session.as_mut() {
                Some(session) => match session.sign(bytes, now) {
                    Ok(signed) => signed,
                    Err(e) => {
                        self.logger
                            .log_error(ip, &format!("{kind} of {qname}: TSIG signing failed: {e}"));
                        return self.transfer_error(msg, ResponseCode::ServerFailure, ip);
                    }
                },
                None => bytes,
            };
            frames.push(frame(&bytes));
        }
        self.metrics.increment_query_counter();
        let how = match &authenticated_by {
            Some(key) => format!("key {key}"),
            None => format!("address {ip}"),
        };
        println!(
            "{kind} of {qname} to {ip}: {records} records in {} message(s), authenticated by {how}",
            frames.len()
        );
        frames
    }

    /// One framed error response to a transfer request.
    fn transfer_error(&self, msg: &DnsMessage, rcode: ResponseCode, ip: IpAddr) -> Vec<Vec<u8>> {
        match self.error_bytes(msg, rcode) {
            Some(bytes) => vec![frame(&bytes)],
            None => {
                self.logger.log_error(ip, "could not serialize an error response");
                Vec::new()
            }
        }
    }

    /// An empty response to `msg` carrying `rcode`, serialized.
    fn error_bytes(&self, msg: &DnsMessage, rcode: ResponseCode) -> Option<Vec<u8>> {
        let mut resp = DnsMessage {
            id: msg.id,
            response: true,
            opcode: msg.opcode,
            authoritive: false,
            truncation: false,
            recursion: msg.recursion,
            recursion_ok: false,
            ad: false,
            cd: msg.cd,
            rcode,
            queries: msg.queries.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        if msg.has_edns() {
            let _ = resp.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
        }
        resp.to_bytes_within(u16::MAX as usize).ok()
    }
}

/// A message with its RFC 1035 §4.2.2 length prefix, in one buffer so the writer
/// emits both in a single call.
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(2 + bytes.len());
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(bytes);
    framed
}

/// An empty TC=1 answer to `request`: the question echoed, no records.
///
/// This is what a client over its response budget gets instead of the answer.
/// It is smaller than the query that asked for it, so it is useless for
/// amplification, and RFC 1035 §4.2.1 has the client retry over TCP — where the
/// handshake proves the source address and the budget no longer applies. Going
/// silent instead would leave a legitimate client with a timeout and no idea that
/// TCP would work.
fn truncated_reply(request: &DnsMessage) -> Option<Vec<u8>> {
    let mut resp = DnsMessage {
        id: request.id,
        response: true,
        opcode: request.opcode,
        authoritive: true,
        truncation: true,
        recursion: request.recursion,
        recursion_ok: false,
        ad: false,
        cd: request.cd,
        rcode: ResponseCode::Ok,
        queries: request.queries.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    if request.has_edns() {
        let _ = resp.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
    }
    resp.to_bytes_within(512).ok()
}

/// Answer a NOTIFY (RFC 1996).
///
/// Three outcomes, and which one applies is a question about *this* zone:
///
/// - **A zone we replicate, from one of its masters** — the message is what it
///   claims to be. NOERROR, and the refresh task is woken so the check happens
///   now instead of when the REFRESH timer next goes off. The serial in the
///   message is not acted on: it is unauthenticated, and the refresh does its own
///   comparison against what the master answers.
/// - **A zone we replicate, from anywhere else** — REFUSED, a policy decision
///   (§3.10 has a secondary log exactly this). A NOTIFY is a spoofable datagram
///   that costs its recipient a transfer, so who may send one is a list, the same
///   way an AXFR's is.
/// - **Anything else** — NOTAUTH, meaning *I am not a secondary for that zone*,
///   which is the truth for a zone we hold as a primary and for one we have never
///   heard of alike. The two are distinguished in the log rather than in the
///   rcode, because they are the same answer to the sender.
///
/// What matters as much is that it is answered *as a NOTIFY*: same opcode, the
/// question echoed, no data (§4.7). Before the opcode decode was fixed this
/// arrived as an `Unknown` opcode and was answered as though it were a lookup for
/// the zone's SOA — a plausible-looking reply to a message that asked nothing.
fn notify_reply(
    msg: &DnsMessage,
    zone_map: &HashMap<String, Zone>,
    secondaries: &Secondaries,
    peer: SocketAddr,
) -> DnsMessage {
    let zone = notify::notified_zone(msg).unwrap_or_default();
    let key = absolute_name(&zone).to_lowercase();

    if let Some(replicated) = secondaries.get(&key) {
        if replicated.masters.contains(&peer.ip()) {
            // `notify_one` rather than waking every waiter: it leaves a permit
            // for a task that is mid-transfer right now, so a NOTIFY that
            // arrives at a busy moment is not simply lost.
            for wake in &replicated.wake {
                wake.notify_one();
            }
            println!("NOTIFY for {zone} from {peer}: refreshing now");
            return notify::notify_response(msg, ResponseCode::Ok);
        }
        println!(
            "NOTIFY for {zone} from {peer}: REFUSED (not one of its masters — \
             a NOTIFY costs its recipient a transfer)"
        );
        return notify::notify_response(msg, ResponseCode::Refused);
    }

    let ours = zone_map
        .values()
        .any(|z| z.origin().eq_ignore_ascii_case(&absolute_name(&zone)));
    let why = if ours {
        "this server is its primary, not a secondary"
    } else {
        "not a zone served here"
    };
    println!("NOTIFY for {zone} from {peer}: NOTAUTH ({why})");
    notify::notify_response(msg, ResponseCode::NotAuthorized)
}

/// A name in absolute form, so it can be compared with a zone origin.
fn absolute_name(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// Receive datagrams and answer each in its own task.
async fn udp_loop(socket: Arc<UdpSocket>, server: Arc<Server>) -> Result<(), std::io::Error> {
    let mut buf = vec![0; UDP_RECEIVE_BUFFER];

    loop {
        let (size, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) if recv_error_is_transient(&e) => continue,
            Err(e) => return Err(e),
        };
        let socket = socket.clone();
        let server = server.clone();
        let packet = buf[0..size].to_vec();

        tokio::spawn(async move {
            // Named for the body below, which was written against separate Arcs
            // when this loop owned its own copy of everything.
            let Server {
                zone_map,
                rate_limiter,
                validator,
                logger,
                metrics,
                tsig_keys,
                response_limiter,
                secondaries,
                ..
            } = &*server;
            // Rate limiting check
            if !rate_limiter.should_allow(peer.ip()) {
                logger.log_rate_limited(peer.ip());
                instrumentation::trace_rate_limit_check(&peer.ip(), false);
                return;
            }
            instrumentation::trace_rate_limit_check(&peer.ip(), true);

            // Validation check
            let validation = validator.validate_packet(&packet, false);
            if !validation.is_valid() {
                logger.log_error(
                    peer.ip(),
                    &format!(
                        "invalid query: {}",
                        validation.error_message().unwrap_or("unknown error")
                    ),
                );
                instrumentation::trace_validation(&peer.ip(), false, validation.error_message());
                return;
            }
            instrumentation::trace_validation(&peer.ip(), true, None);

            if let Ok(msg) = DnsMessage::try_from_bytes(&packet) {
                // Log successful query parsing
                let qtype = msg.queries.first().map(|q| q.qtype);
                logger.log_query(peer.ip(), qtype);

                // A signed query is checked before it is answered, and its answer
                // is signed back (RFC 8945). A rejected one gets NOTAUTH and a
                // TSIG saying which of BADKEY/BADSIG/BADTIME it was.
                let now = tsig::now();
                let mut session = match tsig::check_request(&packet, tsig_keys, now) {
                    TsigCheck::Unsigned => None,
                    TsigCheck::Verified(session) => Some(session),
                    TsigCheck::Rejected(rejection) => {
                        logger.log_error(
                            peer.ip(),
                            &format!(
                                "TSIG rejected (key {}): {}",
                                rejection.key_name(),
                                rejection.error.reason()
                            ),
                        );
                        let mut resp = DnsMessage {
                            id: msg.id,
                            response: true,
                            opcode: msg.opcode,
                            authoritive: false,
                            truncation: false,
                            recursion: msg.recursion,
                            recursion_ok: false,
                            ad: false,
                            cd: msg.cd,
                            rcode: ResponseCode::NotAuthorized,
                            queries: msg.queries.clone(),
                            answers: Vec::new(),
                            authorities: Vec::new(),
                            additionals: Vec::new(),
                        };
                        if msg.has_edns() {
                            let _ = resp.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
                        }
                        if let Ok(bytes) = resp.to_bytes_within(msg.udp_payload_size() as usize) {
                            if let Ok(bytes) = rejection.attach(bytes, now) {
                                let _ = socket.send_to(&bytes, peer).await;
                            }
                        }
                        return;
                    }
                };

                let query_name = msg
                    .queries
                    .first()
                    .map(|q| q.qname.as_str())
                    .unwrap_or("unknown");
                instrumentation::trace_query_received(&peer.ip(), query_name, qtype.unwrap_or(0));

                // Build the response under the zone lock, then drop it before
                // touching the socket: a read guard held across `send_to` would
                // stall a SIGHUP zone reload behind the network.
                let serialized = {
                    let zones = zone_map.read().await;
                    let resp = if msg.opcode == OpCode::Notify {
                        notify_reply(&msg, &zones, secondaries, peer)
                    } else {
                        make_response(&msg, &zones, metrics)
                    };
                    // Honor the client's EDNS0 UDP payload size (512 if no EDNS);
                    // truncates with TC=1 if the response is larger.
                    resp.to_bytes_within(msg.udp_payload_size() as usize)
                };
                match serialized {
                    Ok(bytes) => {
                        // Charge the response, not the query. Over budget, a
                        // truncated reply is the useful refusal: it carries no
                        // records, so it cannot amplify, and a real client reads
                        // TC=1 and asks again over TCP where the handshake proves
                        // who it is. Dropping is for the rest.
                        let reply = match response_limiter.admit(peer.ip(), bytes.len()) {
                            ResponseVerdict::Send => Some(bytes),
                            ResponseVerdict::Truncate => {
                                logger.log_rate_limited(peer.ip());
                                metrics.increment_cache_misses();
                                truncated_reply(&msg)
                            }
                            ResponseVerdict::Drop => {
                                logger.log_rate_limited(peer.ip());
                                instrumentation::trace_rate_limit_check(&peer.ip(), false);
                                None
                            }
                        };
                        // Sign whatever we ended up sending — including a
                        // truncated one, since that is still our answer to a
                        // question someone authenticated.
                        let reply = match (reply, session.as_mut()) {
                            (Some(reply), Some(session)) => match session.sign(reply, now) {
                                Ok(signed) => Some(signed),
                                Err(e) => {
                                    logger.log_error(
                                        peer.ip(),
                                        &format!("TSIG signing failed: {e}"),
                                    );
                                    None
                                }
                            },
                            (reply, _) => reply,
                        };
                        if let Some(reply) = reply {
                            if let Err(e) = socket.send_to(&reply, peer).await {
                                logger.log_error(peer.ip(), &format!("socket send error: {}", e));
                                instrumentation::trace_error(
                                    "socket_send",
                                    Some(&peer.ip()),
                                    &e.to_string(),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        logger.log_error(peer.ip(), &format!("serialization error: {}", e));
                        instrumentation::trace_error(
                            "serialization",
                            Some(&peer.ip()),
                            &e.to_string(),
                        );
                    }
                }
            } else {
                logger.log_error(peer.ip(), "failed to parse DNS message");
                instrumentation::trace_error(
                    "parse_dns_message",
                    Some(&peer.ip()),
                    "failed to parse DNS message",
                );
            }
        });
    }
}

/// What a reload has to redo: everything between reading the files and being
/// ready to answer from them.
///
/// Only SIGHUP reloads, so on a platform without signals this is carried and
/// never used — the same shape the signal handler itself has.
#[derive(Clone)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Reloading {
    replicating: bool,
    allow_partial: bool,
    /// The zones we replicate, and the directory their state sidecar lives in.
    /// A reload re-reads every `.zone` file from disk, so it can resurrect a zone
    /// that was withdrawn for EXPIRE — these are what let it be withdrawn again.
    /// Empty for a server that is nobody's secondary.
    secondaries: Vec<MasterSpec>,
    zone_dir: Option<PathBuf>,
    signing: Option<Arc<ZoneSigning>>,
    validator: Arc<DnssecValidator>,
}

#[cfg_attr(not(unix), allow(dead_code))]
impl Reloading {
    /// Read the zones again and put them through signing and checking, or say
    /// why not.
    ///
    /// Nothing is installed unless the whole set comes through. A reload that
    /// replaced half the zones and gave up would leave the server serving a
    /// mixture of two versions, and the half that failed is the half that
    /// needed attention.
    async fn load(&self, source: &ZoneSource) -> Result<HashMap<String, Zone>, String> {
        let mut zones = load_zones_from_source(source, self.replicating, self.allow_partial)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(signing) = &self.signing {
            signing.apply(&mut zones)?;
        }
        verify_zones(&zones, &self.validator)?;
        Ok(zones)
    }

    /// Re-apply EXPIRE to what was just installed.
    ///
    /// Separate from [`Reloading::load`] because it has to run *after*
    /// `install_all_zones`: the question is about the zones now being served, and
    /// until they are installed there is nothing to withdraw.
    async fn withdraw_unvouched(
        &self,
        zone_map: &Arc<RwLock<HashMap<String, Zone>>>,
        deltas: &Arc<RwLock<DeltaLog>>,
    ) {
        let Some(zone_dir) = &self.zone_dir else {
            return;
        };
        if self.secondaries.is_empty() {
            return;
        }
        withdraw_unvouched_zones(&self.secondaries, zone_map, deltas, zone_dir).await;
    }
}

/// Spawn a signal handler task to reload zones on SIGHUP (Unix only)
#[cfg(unix)]
fn spawn_signal_handler(
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    deltas: Arc<RwLock<DeltaLog>>,
    source: ZoneSource,
    notify_targets: Vec<SocketAddr>,
    announced: Vec<(String, u32)>,
    reloading: Reloading,
) {
    let zone_map_clone = Arc::clone(&zone_map);
    let source_clone = source.clone();
    tokio::spawn(async move {
        let mut announced = announced;
        if let Ok(mut signals) = Signals::new(&[SIGHUP]) {
            while signals.next().await.is_some() {
                match reloading.load(&source_clone).await {
                    Ok(new_zones) => {
                        // A reload is a version step like any other: the
                        // difference from what we were serving is what an IXFR
                        // will answer with, and this is the only moment both
                        // versions exist.
                        install_all_zones(&zone_map_clone, &deltas, new_zones).await;
                        // A reload re-reads the files, so a zone withdrawn for
                        // EXPIRE is back in the map at this point. Judge it
                        // again before anything is announced or answered.
                        reloading.withdraw_unvouched(&zone_map_clone, &deltas).await;
                        println!("Zones reloaded via SIGHUP");
                        instrumentation::trace_info("zones_reloaded", "SIGHUP signal");
                        // The point of reloading is that something changed, so
                        // this is exactly when a secondary wants to hear about it.
                        announced =
                            announce_zones(&zone_map_clone, &announced, &notify_targets).await;
                    }
                    Err(e) => {
                        // The zones already loaded keep answering. A reload
                        // that failed is a file that changed for the worse, and
                        // the version in memory is the last one known good.
                        eprintln!("Failed to reload zones: {e}");
                        instrumentation::trace_error("zone_reload_failed", None, &e);
                    }
                }
            }
        }
    });
}

/// No-op signal handler for non-Unix platforms
#[cfg(not(unix))]
fn spawn_signal_handler(
    _zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    _deltas: Arc<RwLock<DeltaLog>>,
    _source: ZoneSource,
    _notify_targets: Vec<SocketAddr>,
    _announced: Vec<(String, u32)>,
    _reloading: Reloading,
) {
    // Signal handling not supported on this platform, so a zone change is only
    // announced at startup here.
}

/// `addr` or `addr:port` for a secondary, defaulting to port 53.
///
/// A bare IPv6 address has colons of its own, so `[::1]:5353` is the only
/// unambiguous way to give one a port — which is what `SocketAddr` already
/// parses, so the shape is the familiar one rather than a new convention.
fn parse_notify_targets(specs: &[String]) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let mut targets = Vec::new();
    for spec in specs {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        if let Ok(addr) = spec.parse::<SocketAddr>() {
            targets.push(addr);
            continue;
        }
        match spec.parse::<IpAddr>() {
            Ok(ip) => targets.push(SocketAddr::new(ip, 53)),
            Err(e) => {
                return Err(Box::from(format!(
                    "--also-notify {spec:?} is not an address or address:port: {e}"
                )))
            }
        }
    }
    Ok(targets)
}

/// Tell every secondary about the zones whose serial moved since `announced`,
/// and return the serials now announced.
///
/// Called after each load. A zone whose serial did not move is not news, and one
/// that went backwards is not either — a secondary compares serials and would
/// ignore it, so sending would be noise.
async fn announce_zones(
    zone_map: &Arc<RwLock<HashMap<String, Zone>>>,
    announced: &[(String, u32)],
    targets: &[SocketAddr],
) -> Vec<(String, u32)> {
    let (current, pending) = {
        let zones = zone_map.read().await;
        let all: Vec<&Zone> = zones.values().collect();
        let current = notify::zone_serials(&all);
        let changed = notify::changed_zones(announced, &current);
        // Build the messages under the lock, send them outside it: a NOTIFY that
        // goes unanswered takes seconds to retry, and holding the zone map that
        // long would block a reload behind the network.
        let pending: Vec<(String, u32, Option<rdns::ResourceRecord>)> = changed
            .iter()
            .filter_map(|(name, serial)| {
                zones
                    .get(name)
                    .map(|zone| (name.clone(), *serial, notify::soa_record(zone)))
            })
            .collect();
        (current, pending)
    };

    if targets.is_empty() || pending.is_empty() {
        return current;
    }
    for (zone, serial, soa) in pending {
        for target in targets {
            let target = *target;
            let zone = zone.clone();
            let soa = soa.clone();
            tokio::spawn(async move {
                send_notify(&zone, serial, soa, target).await;
            });
        }
    }
    current
}

/// Tell the configured secondaries that a zone *we* replicate has moved.
///
/// RFC 1996 §3.2's "master" is whoever serves the zone to someone, which a
/// secondary in the middle of a tree is. Without this, `announce_zones` covers
/// only the moments a *primary* learns of a change — startup and SIGHUP — while a
/// secondary learns of one by transferring it and says nothing, so the first
/// level of a tree updates at once and every level below it waits out a refresh
/// timer.
///
/// Spawned rather than awaited for the same reason the primary's announcements
/// are: an unanswered NOTIFY takes seconds to give up on, and a refresh should
/// not be held behind the network to tell somebody about work it has finished.
fn announce_transfer(
    zone: &str,
    serial: u32,
    soa: Option<ResourceRecord>,
    targets: &[SocketAddr],
) {
    for target in targets {
        let (zone, soa, target) = (zone.to_string(), soa.clone(), *target);
        tokio::spawn(async move {
            send_notify(&zone, serial, soa, target).await;
        });
    }
}

/// Send one NOTIFY, retrying until it is acknowledged (RFC 1996 §3.6).
///
/// Any rcode is an acknowledgement: a secondary answering NOTAUTH has still
/// received the message, and repeating it would not change its mind. Giving up
/// after [`notify::NOTIFY_ATTEMPTS`] is safe because the secondary's refresh timer
/// is the backstop this is an optimisation over.
async fn send_notify(
    zone: &str,
    serial: u32,
    soa: Option<rdns::ResourceRecord>,
    target: SocketAddr,
) {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid bind address")
    } else {
        "[::]:0".parse().expect("valid bind address")
    };
    let Ok(socket) = UdpSocket::bind(bind).await else {
        eprintln!("NOTIFY {zone} to {target}: could not open a socket");
        return;
    };

    let mut wait = Duration::from_secs(notify::NOTIFY_RETRY_SECS);
    for attempt in 1..=notify::NOTIFY_ATTEMPTS {
        let id = rand_id();
        let msg = notify::notify_request(zone, soa.clone(), id);
        let mut buf = vec![0u8; 512];
        let Ok(len) = msg.to_bytes(&mut buf) else {
            eprintln!("NOTIFY {zone}: could not serialize");
            return;
        };
        if socket.send_to(&buf[..len], target).await.is_err() {
            eprintln!("NOTIFY {zone} to {target}: send failed");
            return;
        }

        let mut reply = vec![0u8; 512];
        // Something answered, but not this? Treat it as no answer rather than as
        // an acknowledgement: an off-path reply should not be able to silence a
        // notification.
        if let Ok(Ok((n, _))) = tokio::time::timeout(wait, socket.recv_from(&mut reply)).await {
            if let Ok(parsed) = DnsMessage::try_from_bytes(&reply[..n]) {
                if notify::acknowledges(&parsed, id) {
                    println!(
                        "NOTIFY {zone} serial {serial} to {target}: acknowledged ({:?})",
                        parsed.rcode
                    );
                    return;
                }
            }
        }
        if attempt < notify::NOTIFY_ATTEMPTS {
            wait *= 2;
        }
    }
    eprintln!(
        "NOTIFY {zone} serial {serial} to {target}: no acknowledgement after {} attempts",
        notify::NOTIFY_ATTEMPTS
    );
}

// ---------------------------------------------------------------------------
// The secondary role
// ---------------------------------------------------------------------------

/// Replace one zone, recording what changed.
///
/// The only way a zone should ever enter the map once the server is running.
/// Both halves happen under the same pair of locks and in the same call, because
/// the delta log is *derived* from the zone map: a swap that skipped it would
/// leave us offering an IXFR chain that does not describe the zone we serve — and
/// a secondary applying that chain would end up with a zone that never existed,
/// holding a serial saying it is current.
async fn install_zone(
    zone_map: &Arc<RwLock<HashMap<String, Zone>>>,
    deltas: &Arc<RwLock<DeltaLog>>,
    zone: Zone,
) {
    let mut zones = zone_map.write().await;
    let mut log = deltas.write().await;

    let key = zones
        .keys()
        .find(|k| k.eq_ignore_ascii_case(zone.origin()))
        .cloned();
    let previous = key.as_ref().and_then(|k| zones.get(k));
    log.note_change(previous, &zone);

    if let Some(key) = key {
        zones.remove(&key);
    }
    zones.insert(zone.origin().to_string(), zone);
}

/// Replace every zone, as a reload does, recording what changed in each.
///
/// A zone that has gone from the configuration takes its history with it: we no
/// longer serve it, so we have no increments of it to offer.
// Reached only from the SIGHUP handler, which exists on Unix — the reload it
// serves has no trigger on Windows, so there it is genuinely unreachable rather
// than merely unused.
#[cfg_attr(not(unix), allow(dead_code))]
async fn install_all_zones(
    zone_map: &Arc<RwLock<HashMap<String, Zone>>>,
    deltas: &Arc<RwLock<DeltaLog>>,
    new_zones: HashMap<String, Zone>,
) {
    let mut zones = zone_map.write().await;
    let mut log = deltas.write().await;

    for old_name in zones.keys() {
        if !new_zones
            .values()
            .any(|z| z.origin().eq_ignore_ascii_case(old_name))
        {
            log.forget(old_name);
        }
    }
    for zone in new_zones.values() {
        let previous = zones
            .keys()
            .find(|k| k.eq_ignore_ascii_case(zone.origin()))
            .and_then(|k| zones.get(k));
        log.note_change(previous, zone);
    }

    *zones = new_zones;
}

/// One replicated zone, as a NOTIFY needs to see it.
struct ReplicatedZone {
    /// The addresses a NOTIFY for this zone is believed from — the masters it is
    /// configured to come from, and nobody else.
    masters: Vec<IpAddr>,
    /// One per refresh task, since a zone may have several masters and each is
    /// checked on its own timer.
    wake: Vec<Arc<Notify>>,
}

/// Replicated zones by lowercased origin.
type Secondaries = Arc<HashMap<String, ReplicatedZone>>;

/// What every refresh task shares with the server and with each other.
///
/// Bundled rather than passed as six parameters because they are one thing —
/// the state a replicated zone is maintained *in* — and because the pieces are
/// not independently choosable: the delta log is derived from the zone map, and
/// the sidecar lives in the zone directory. A signature that let a caller supply
/// four of them and forget the fifth would be inviting exactly the drift the
/// swap helpers exist to prevent.
#[derive(Clone)]
struct Replication {
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    deltas: Arc<RwLock<DeltaLog>>,
    /// One file, so one mutex: the rule that made step 1 of #7 necessary applies
    /// inside a process too.
    state: Arc<Mutex<StateFile>>,
    zone_dir: PathBuf,
    /// Who to tell when a zone we replicate moves — we are its master to them.
    notify_targets: Vec<SocketAddr>,
}

/// Start a refresh task per (zone, master), and return what a NOTIFY needs to
/// find them.
///
/// The state file is shared behind one mutex because it is one file, and the
/// rule that made step 1 of this work necessary applies just as much inside a
/// process: one writer.
fn spawn_secondaries(
    specs: Vec<MasterSpec>,
    keys: &TsigKeyring,
    replication: Replication,
) -> Result<Secondaries, Box<dyn std::error::Error>> {
    let mut registry: HashMap<String, ReplicatedZone> = HashMap::new();

    for spec in specs {
        // A key named but not defined is a configuration error, not a reason to
        // transfer unsigned: the operator asked for authentication and would
        // have no way to see that they did not get it.
        let key = match &spec.key_name {
            Some(name) => Some(
                keys.get(&absolute_name(name), TsigAlgorithm::HmacSha256)
                    .or_else(|| {
                        [
                            TsigAlgorithm::HmacSha1,
                            TsigAlgorithm::HmacSha384,
                            TsigAlgorithm::HmacSha512,
                        ]
                        .into_iter()
                        .find_map(|alg| keys.get(&absolute_name(name), alg))
                    })
                    .ok_or_else(|| {
                        format!(
                            "--secondary names TSIG key {name:?}, which no --tsig-key defines"
                        )
                    })?
                    .clone(),
            ),
            None => None,
        };

        let wake = Arc::new(Notify::new());
        let entry = registry
            .entry(spec.zone.to_lowercase())
            .or_insert_with(|| ReplicatedZone {
                masters: Vec::new(),
                wake: Vec::new(),
            });
        entry.masters.push(spec.master.ip());
        entry.wake.push(wake.clone());

        println!(
            "secondary for {} from {}{}",
            spec.zone,
            spec.master,
            match &spec.key_name {
                Some(name) => format!(" signed with {name}"),
                None => String::new(),
            }
        );

        tokio::spawn(secondary_loop(spec, key, replication.clone(), wake));
    }

    Ok(Arc::new(registry))
}

/// Keep one zone in step with one master, forever.
///
/// The cycle is RFC 1035 §4.3.5's: ask for the SOA, compare serials, transfer if
/// behind, then sleep on REFRESH — or on RETRY if anything failed, with a NOTIFY
/// cutting the wait short. What makes it a *replica* rather than a cache is the
/// third timer: out of contact past EXPIRE, the zone stops being served at all.
async fn secondary_loop(
    spec: MasterSpec,
    key: Option<TsigKey>,
    replication: Replication,
    wake: Arc<Notify>,
) {
    // What the EXPIRE clock counts from when we have never reached the master:
    // process start. Not "forever ago", which would withdraw a zone we hold
    // before ever trying, and not "never expires", which would serve a copy of
    // unknown age indefinitely because we happened to restart.
    let started_at = current_unix_timestamp();

    loop {
        let result = refresh_once(&spec, key.as_ref(), &replication).await;

        // The timers are read *after* the refresh, not before, because the
        // refresh may have just installed the zone that defines them. Read first,
        // the very first transfer of a zone is followed by the default hour's
        // wait instead of the REFRESH the zone actually asks for — which is
        // invisible in a test that only checks the transfer happened, and was
        // caught by watching a zone with a one-minute REFRESH sit there for an
        // hour.
        let timers = zone_timers(&replication.zone_map, &spec.zone).await;

        let wait = match result {
            Ok(outcome) => {
                println!("secondary {}: {outcome} (from {})", spec.zone, spec.master);
                timers.after_success()
            }
            Err(e) => {
                eprintln!("secondary {} from {}: {e}", spec.zone, spec.master);
                expire_if_out_of_contact(&spec, &replication, started_at, timers).await;
                timers.after_failure()
            }
        };

        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = wake.notified() => {}
        }
    }
}

/// The timers the zone we currently hold asks for, or the defaults if we hold
/// none — a zone we have never fetched has no SOA to obey.
async fn zone_timers(zone_map: &Arc<RwLock<HashMap<String, Zone>>>, zone: &str) -> RefreshTimers {
    zone_map
        .read()
        .await
        .values()
        .find(|z| z.origin().eq_ignore_ascii_case(zone))
        .and_then(RefreshTimers::from_zone)
        .unwrap_or_default()
}

/// One refresh: probe, compare, and transfer if there is anything to transfer.
async fn refresh_once(
    spec: &MasterSpec,
    key: Option<&TsigKey>,
    replication: &Replication,
) -> Result<String, String> {
    let Replication {
        zone_map,
        deltas,
        state,
        zone_dir,
        notify_targets,
    } = replication;
    // A clone rather than a borrow: an incremental transfer applies its changes
    // to this version, and holding the read lock across a network round trip
    // would block every reload and every swap for the length of the transfer.
    let base = zone_map
        .read()
        .await
        .values()
        .find(|z| z.origin().eq_ignore_ascii_case(&spec.zone))
        .cloned();
    let held = base.as_ref().and_then(Zone::serial);

    let remote = xfr::fetch_soa(spec.master, &spec.zone, key).await?;
    let now = current_unix_timestamp();

    // Reaching the master is what the EXPIRE clock resets on, whether or not
    // there was anything new to fetch — the zone is confirmed current, which is
    // exactly what "not stale" means.
    if let Some(held) = held {
        if !is_newer(remote, held) {
            record_state(state, spec, held, now)?;
            return Ok(format!("serial {held} is current"));
        }
    }

    // Ask for the difference when we have a version to differ from, and for the
    // whole zone when we do not. The master may answer either request with the
    // whole zone (RFC 1995 §4), so this is a preference rather than a demand —
    // which is why there is one code path below and not two.
    let mut note = String::new();
    let fetched = match &base {
        Some(base) => match xfr::fetch_changes(spec.master, base, key).await? {
            xfr::IxfrOutcome::UpToDate(serial) => {
                // The SOA probe said otherwise a moment ago, so the master
                // changed its mind between the two questions. Nothing to do, and
                // the next refresh will see the newer serial.
                record_state(state, spec, serial, now)?;
                return Ok(format!("serial {serial} is current (the master says so)"));
            }
            xfr::IxfrOutcome::Updated {
                zone,
                steps,
                missing_deletions,
            } => {
                note = format!(", {steps} incremental step(s)");
                if missing_deletions > 0 {
                    // Worth saying out loud: it means our copy and the master's
                    // had already diverged. Not worth failing over — the records
                    // are meant to be gone either way.
                    note.push_str(&format!(
                        ", {missing_deletions} deletion(s) we did not hold"
                    ));
                }
                zone
            }
            xfr::IxfrOutcome::FullTransfer(zone) => {
                note = ", sent in full".to_string();
                zone
            }
        },
        None => xfr::fetch_zone(spec.master, &spec.zone, key).await?,
    };

    let serial = fetched
        .serial()
        .ok_or_else(|| "the transferred zone has no SOA".to_string())?;

    // Persist before serving. Both orders are safe — a crash between them costs
    // at most a refetch — but this way the state line, written last, is only ever
    // true after both the file and memory agree with it.
    let path = zone_file_path(zone_dir, &spec.zone);
    write_zone_file(&fetched, &path)?;

    let count = fetched.records().len();
    // The swap is a whole-zone replacement under the write lock: readers see the
    // old zone or the new one and never a half-applied transfer. Nothing removes
    // records one at a time, which is also why `Zone` has no API to.
    //
    // The delta is computed here, while both versions are in hand — this is the
    // only moment they both exist, and the difference is what lets us answer an
    // IXFR for this step to our own downstream secondaries. That composition is
    // the point: a secondary that can serve increments of a zone it received is
    // an interior node of a replication tree rather than a leaf.
    let soa = notify::soa_record(&fetched);
    install_zone(zone_map, deltas, fetched).await;
    record_state(state, spec, serial, now)?;

    // We are this zone's master to whoever replicates it from us, and the serial
    // just moved forward — which is the whole of what a NOTIFY says.
    announce_transfer(&spec.zone, serial, soa, notify_targets);

    Ok(match held {
        Some(held) => format!("transferred serial {held} -> {serial}, {count} records{note}"),
        None => format!("transferred serial {serial}, {count} records{note}"),
    })
}

fn record_state(
    state: &Arc<Mutex<StateFile>>,
    spec: &MasterSpec,
    serial: u32,
    now: u64,
) -> Result<(), String> {
    state.lock().expect("state mutex").record(TransferState {
        zone: spec.zone.clone(),
        serial,
        refreshed_at: now,
        master: spec.master,
    })
}

/// Stop serving a zone we have not been able to reach for longer than its
/// EXPIRE.
///
/// This is the one place a secondary is *required* to make things worse for its
/// clients, and the reason is that the alternative is worse still: a zone served
/// with AA set is a claim to be current, and a server that keeps making that
/// claim indefinitely turns a primary's outage into permanently wrong answers
/// nobody can see is wrong. Withdrawn, the same query gets REFUSED, which sends
/// a resolver to the other nameservers in the delegation.
///
/// The state line is deliberately left behind: it records when contact was last
/// made, which is what lets a restart notice the zone is still expired instead of
/// reading "nothing known" as "fetch and serve".
async fn expire_if_out_of_contact(
    spec: &MasterSpec,
    replication: &Replication,
    started_at: u64,
    timers: RefreshTimers,
) {
    let Replication {
        zone_map,
        deltas,
        state,
        ..
    } = replication;
    let last_contact = state
        .lock()
        .expect("state mutex")
        .get(&spec.zone, spec.master)
        .map(|s| s.refreshed_at)
        .unwrap_or(started_at);

    if !timers.has_expired(last_contact, current_unix_timestamp()) {
        return;
    }

    let mut zones = zone_map.write().await;
    let held = zones
        .keys()
        .find(|k| k.eq_ignore_ascii_case(&spec.zone))
        .cloned();
    if let Some(key) = held {
        zones.remove(&key);
        // The increments go with it: offering a chain for a zone we have
        // withdrawn would be answering for something we just stopped serving.
        deltas.write().await.forget(&spec.zone);
        eprintln!(
            "secondary {}: EXPIRE ({}s) passed with no contact — no longer serving this zone",
            spec.zone, timers.expire
        );
    }
}

/// Withdraw every replicated zone whose age we cannot vouch for.
///
/// **Called after each time the zone map is filled from disk** — at startup and
/// after every reload — because that is exactly when a file whose contents
/// expired can come back. It used to run from `main` only, so a `SIGHUP` re-read
/// every `.zone` file and served it again without consulting the sidecar: a zone
/// correctly withdrawn because its primary had been unreachable for a week came
/// straight back, **with AA set**, which is the "permanently wrong answers nobody
/// can see are wrong" the withdrawal exists to prevent. Expiry that lasts only
/// until the next deploy is not expiry.
///
/// Two ways a zone fails to earn an answer, and the second one was the hole:
///
/// - Its last successful contact is older than the SOA's EXPIRE. The plain case.
/// - **There is no record of contact at all**, while the zone is loaded — so it
///   came off disk. A missing sidecar, an unreadable one, or an entry for another
///   master all land here. `StateFile::load` returns empty by design and never
///   fails, which is right for a cache and wrong for expiry: forgetting the
///   last-contact time *is* the difference between withdrawn and served, so
///   unknown age has to mean "do not serve" rather than "serve and hope". The
///   zone comes back at the first successful transfer, which is seconds away and
///   is the thing that makes it ours to answer for.
///
/// A zone we hold but do not replicate is never touched: the loop is over the
/// `--secondary` specs, so a primary zone sharing the directory is not this
/// function's business.
async fn withdraw_unvouched_zones(
    specs: &[MasterSpec],
    zone_map: &Arc<RwLock<HashMap<String, Zone>>>,
    deltas: &Arc<RwLock<DeltaLog>>,
    zone_dir: &Path,
) {
    let state = StateFile::load(&state_file_path(zone_dir));
    let now = current_unix_timestamp();

    for spec in specs {
        let timers = zone_timers(zone_map, &spec.zone).await;
        let why = match state.get(&spec.zone, spec.master) {
            Some(entry) if timers.has_expired(entry.refreshed_at, now) => format!(
                "the copy on disk expired {}s ago",
                now.saturating_sub(entry.refreshed_at + timers.expire)
            ),
            Some(_) => continue,
            None => "there is no record of ever having transferred it, so its age is \
                     unknown"
                .to_string(),
        };

        let mut zones = zone_map.write().await;
        let held = zones
            .keys()
            .find(|k| k.eq_ignore_ascii_case(&spec.zone))
            .cloned();
        if let Some(key) = held {
            zones.remove(&key);
            // The increments go with it, for the same reason as in `expire_zone`:
            // offering a chain for a zone we have withdrawn would be answering
            // for something we just stopped serving.
            deltas.write().await.forget(&spec.zone);
            eprintln!(
                "secondary {}: {why} — not serving it until {} answers",
                spec.zone, spec.master
            );
        }
    }
}

/// A transaction id for a NOTIFY. Random, for the same reason a query's is.
fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // A full CSPRNG is overkill for a message we also match by source and opcode,
    // and the workspace's `rand` is a library dependency rather than this crate's.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (nanos >> 16)) as u16
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Key generation is a mode, not a server option: nothing is served, and it
    // happens once per zone before anything else can.
    if let Some(zone) = &cli.generate_keys {
        let dir = cli
            .signing_key_dir
            .as_deref()
            .ok_or("--generate-keys needs --signing-key-dir")?;
        return generate_keys(zone, dir, &cli.key_algorithm);
    }

    validate_cli_args(&cli.host, cli.port)?;
    // A typo in either list stops the server rather than quietly narrowing it —
    // or, worse, being read as something wider.
    let transfer_acl =
        TransferAcl::parse(&cli.allow_transfer).map_err(Box::<dyn std::error::Error>::from)?;
    let tsig_keys = TsigKeyring::parse(&cli.tsig_key).map_err(Box::<dyn std::error::Error>::from)?;
    let notify_targets = parse_notify_targets(&cli.also_notify)?;

    let secondary_specs = parse_secondary_specs(&cli.secondary)?;

    let replicating = !secondary_specs.is_empty();
    // Read before the source is taken apart, which consumes the two path
    // fields.
    let signing = ZoneSigning::load(&cli)?.map(Arc::new);
    let source = validate_zone_source(cli.zone_file, cli.zone_dir, replicating)?;
    let mut zones = load_zones_from_source(&source, replicating, cli.allow_partial_load).await?;

    // Signing happens between loading and serving, and so does checking the
    // result: verifying what we just produced is what catches a canonicalization
    // bug here rather than at every validator on the internet.
    if let Some(signing) = &signing {
        signing.apply(&mut zones)?;
    }
    let mut validator = DnssecValidator::new(cli.require_signed || signing.is_some());
    validator.set_require_signed(cli.require_signed);
    let validator = Arc::new(validator);
    verify_zones(&zones, &validator)?;

    let zone_map = Arc::new(RwLock::new(zones));
    // Empty at startup by design: the deltas are between versions *this process*
    // has held, and a zone read from disk has no previous version here. Every
    // secondary asking for an increment across a restart gets a full transfer
    // instead, which RFC 1995 §4 permits unconditionally and which corrects
    // itself at the next change. See "Architecture: incremental transfer".
    let deltas = Arc::new(RwLock::new(DeltaLog::new()));
    let addr = format!("{}:{}", cli.host, cli.port);

    // Before anything is served: a replicated zone whose copy on disk went out
    // of contact past its EXPIRE is not ours to answer for, however recently the
    // process started.
    let mut reload_secondaries: Vec<MasterSpec> = Vec::new();
    let mut reload_zone_dir: Option<PathBuf> = None;
    let secondaries = if secondary_specs.is_empty() {
        Arc::new(HashMap::new())
    } else {
        let ZoneSource::Directory(dir) = &source else {
            // `validate_zone_source` has already refused this combination; this
            // is the compiler being told so.
            return Err(Box::from("--secondary requires --zone-dir"));
        };
        let zone_dir = PathBuf::from(dir);
        withdraw_unvouched_zones(&secondary_specs, &zone_map, &deltas, &zone_dir).await;
        reload_secondaries = secondary_specs.clone();
        reload_zone_dir = Some(zone_dir.clone());
        let replication = Replication {
            zone_map: zone_map.clone(),
            deltas: deltas.clone(),
            state: Arc::new(Mutex::new(StateFile::load(&state_file_path(&zone_dir)))),
            zone_dir,
            notify_targets: notify_targets.clone(),
        };
        spawn_secondaries(secondary_specs, &tsig_keys, replication)?
    };

    // A zone that has just been loaded is news to every secondary, which is why
    // this runs at startup and not only on reload.
    let announced = announce_zones(&zone_map, &[], &notify_targets).await;

    // Zone reload on SIGHUP, where signals exist.
    spawn_signal_handler(
        zone_map.clone(),
        deltas.clone(),
        source,
        notify_targets,
        announced,
        Reloading {
            replicating,
            allow_partial: cli.allow_partial_load,
            secondaries: reload_secondaries,
            zone_dir: reload_zone_dir,
            signing,
            validator,
        },
    );

    serve(
        &addr,
        zone_map,
        transfer_acl,
        tsig_keys,
        cli.response_rate,
        secondaries,
        deltas,
    )
    .await
}

/// Parse every `--secondary`, or stop.
///
/// A spec that does not parse is an error rather than a skip, for the same
/// reason a malformed ACL rule is: a secondary that silently is not replicating
/// a zone it was told to replicate is a failure nobody notices until the day the
/// primary is gone.
fn parse_secondary_specs(specs: &[String]) -> Result<Vec<MasterSpec>, Box<dyn std::error::Error>> {
    specs
        .iter()
        .filter(|spec| !spec.trim().is_empty())
        .map(|spec| {
            MasterSpec::parse(spec)
                .map_err(|e| Box::<dyn std::error::Error>::from(format!("--secondary {e}")))
        })
        .collect()
}

fn validate_cli_args(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // Port must be 1-65535 (0 is reserved)
    if port == 0 {
        return Err(Box::from("Port must be in range 1-65535"));
    }
    
    // Host must be valid IP or hostname (basic validation)
    // This is a simple check; more complex validation could parse as IP
    if host.is_empty() {
        return Err(Box::from("Host cannot be empty"));
    }
    
    // Very basic hostname/IP validation - just check for invalid characters
    // Valid hostnames: alphanumeric, dots, hyphens, colons (for IPv6)
    if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '%') {
        return Err(Box::from(format!("Invalid host format: {}", host)));
    }
    
    Ok(())
}

/// Validate that exactly one of zone_file or zone_dir is specified
///
/// `replicating` is whether any `--secondary` was given, which narrows this: a
/// fetched zone has to be written somewhere, and a single `--zone-file` is not a
/// place to put a zone whose name we may not have seen yet.
fn validate_zone_source(
    zone_file: Option<String>,
    zone_dir: Option<String>,
    replicating: bool,
) -> Result<ZoneSource, Box<dyn std::error::Error>> {
    if replicating && zone_dir.is_none() {
        return Err(Box::from(
            "--secondary needs --zone-dir: a transferred zone is written to disk, \
             and --zone-file names one file rather than somewhere to put them",
        ));
    }
    match (zone_file, zone_dir) {
        (Some(file), None) => {
            // Check if file exists
            if !Path::new(&file).exists() {
                return Err(Box::from(format!("Zone file not found: {}", file)));
            }
            Ok(ZoneSource::SingleFile(file))
        }
        (None, Some(dir)) => {
            // Check if directory exists
            if !Path::new(&dir).is_dir() {
                return Err(Box::from(format!("Zone directory not found or not a directory: {}", dir)));
            }
            Ok(ZoneSource::Directory(dir))
        }
        (Some(_), Some(_)) => {
            Err(Box::from("Cannot specify both --zone-file and --zone-dir"))
        }
        (None, None) => {
            Err(Box::from("Must specify either --zone-file or --zone-dir"))
        }
    }
}

/// Zone signing as configured: which keys, for how long, and which chain.
///
/// Only zones loaded from disk are signed. A zone that arrived by transfer is
/// the master's, signatures included — re-signing it here would replace a
/// statement its owner made with one we made about data we do not own, and the
/// parent's DS points at their key, not ours.
struct ZoneSigning {
    /// Keys by the zone they are published at, down-cased.
    keys: HashMap<String, Vec<SigningKey>>,
    validity: u64,
    chain: DenialChain,
}

impl ZoneSigning {
    fn load(cli: &Cli) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let Some(dir) = &cli.signing_key_dir else {
            return Ok(None);
        };
        let loaded = SigningKey::load_dir(dir).map_err(|e| format!("{e:#}"))?;
        if loaded.is_empty() {
            // Not an error — a key directory prepared before any key is in it
            // is a reasonable state — but silence here would look exactly like
            // signing that quietly did nothing.
            eprintln!(
                "No .{} files in {}: no zone will be signed",
                rdns::dnssec_key::KEY_FILE_EXTENSION,
                dir.display()
            );
        }
        let mut keys: HashMap<String, Vec<SigningKey>> = HashMap::new();
        for key in loaded {
            keys.entry(key.owner().to_ascii_lowercase())
                .or_default()
                .push(key);
        }
        Ok(Some(ZoneSigning {
            keys,
            validity: u64::from(cli.signature_validity) * 86_400,
            chain: if cli.nsec3 {
                DenialChain::Nsec3 {
                    salt: Vec::new(),
                    iterations: 0,
                    opt_out: cli.nsec3_opt_out,
                }
            } else {
                DenialChain::Nsec
            },
        }))
    }

    /// Sign every zone there are keys for, in place.
    ///
    /// A zone we hold keys for and cannot sign is an error rather than a zone
    /// served unsigned: its parent has a DS pointing at one of these keys, so
    /// the unsigned answer would be bogus at every validating client rather
    /// than merely unvalidated.
    fn apply(&self, zones: &mut HashMap<String, Zone>) -> Result<(), String> {
        let policy = SigningPolicy::valid_for(current_unix_timestamp(), self.validity)
            .with_chain(self.chain.clone());
        for (origin, zone) in zones.iter_mut() {
            let Some(keys) = self.keys.get(&origin.to_ascii_lowercase()) else {
                continue;
            };
            *zone = sign_zone(zone, keys, &policy)
                .map_err(|e| format!("signing {origin}: {e:#}"))?;
            println!(
                "Signed {origin} with {} key{}",
                keys.len(),
                if keys.len() == 1 { "" } else { "s" }
            );
        }
        Ok(())
    }
}

/// Check every signature in every zone before anything is served from it.
///
/// The question asked is "does each signature in this zone cover an RRset that
/// verifies", not "is every RRset signed" — a delegation's NS RRset and the
/// glue below it carry no signature by design, and demanding one would fail
/// every zone with a child. What this catches is the case worth catching: a
/// zone whose signatures have expired, or were made over data that has since
/// been edited, which otherwise keeps answering as though nothing happened.
fn verify_zones(
    zones: &HashMap<String, Zone>,
    validator: &DnssecValidator,
) -> Result<(), String> {
    if !validator.is_enabled() {
        return Ok(());
    }
    for (origin, zone) in zones {
        let signed = DnssecValidator::is_zone_signed(zone);
        if !signed {
            // `validate_response` gives the same verdict; asking it with no
            // records keeps the "is unsigned acceptable" decision in one place.
            let (ok, _) = validator.validate_response(zone, &[], origin);
            if !ok {
                return Err(format!("{origin} is not signed"));
            }
            continue;
        }

        let mut checked = 0usize;
        for (name, rtype) in signed_rrsets(zone) {
            let records = zone.query(&name, rtype);
            if records.is_empty() {
                return Err(format!(
                    "{origin}: a signature covers the {rtype} RRset at {name}, which is not there"
                ));
            }
            let (ok, _) = validator.validate_response(zone, &records, &name);
            if !ok {
                return Err(format!(
                    "{origin}: the {rtype} RRset at {name} does not verify against the zone's \
                     own keys"
                ));
            }
            checked += 1;
        }
        println!("Verified {checked} signed RRsets in {origin}");
    }
    Ok(())
}

/// Every `(owner, type)` in the zone that some RRSIG claims to cover.
fn signed_rrsets(zone: &Zone) -> Vec<(String, u16)> {
    let mut seen: Vec<(String, u16)> = zone
        .records()
        .iter()
        .filter(|r| r.rdata.rtype == record_types::RRSIG)
        .filter_map(|r| {
            rdns::dnssec::Rrsig::from_record(&ResourceRecord {
                name: r.name.clone(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.clone(),
            })
        })
        .map(|sig| (sig.owner, sig.type_covered))
        .collect();
    seen.sort();
    seen.dedup();
    seen
}

/// Make a key-signing and a zone-signing key for `zone`, and say what to give
/// the parent.
///
/// Two keys rather than one because that is what lets the data key roll without
/// the parent being involved: only the key-signing key is digested into the DS,
/// so the zone-signing key can be replaced whenever, while replacing the other
/// means a conversation with the registrar.
fn generate_keys(
    zone: &str,
    dir: &Path,
    algorithm: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let algorithm = SigningAlgorithm::parse(algorithm).map_err(|e| format!("{e:#}"))?;
    let zone = if zone.ends_with('.') {
        zone.to_string()
    } else {
        format!("{zone}.")
    };

    let ksk = SigningKey::generate(algorithm, &zone, DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP)
        .map_err(|e| format!("{e:#}"))?;
    let zsk =
        SigningKey::generate(algorithm, &zone, DNSKEY_FLAG_ZONE).map_err(|e| format!("{e:#}"))?;
    for key in [&ksk, &zsk] {
        let path = key.write_to_dir(dir).map_err(|e| format!("{e:#}"))?;
        println!("Wrote {}", path.display());
    }

    // SHA-256, which RFC 8624 §3.3 is the only digest that is both mandatory to
    // implement and not deprecated.
    let ds = ksk.ds(2).map_err(|e| format!("{e:#}"))?;
    println!("\nGive the parent zone this DS record:\n");
    println!(
        "{} IN DS {} {} {} {}",
        ds.owner,
        ds.key_tag,
        ds.algorithm,
        ds.digest_type,
        ds.digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    );
    println!(
        "\nUntil it is published, {zone} is signed but insecure: a validator has no way to \
         reach these keys."
    );
    Ok(())
}

/// Load zones from source (single file or directory)
///
/// Three questions that used to be one, and conflating them is what let a broken
/// zone file pass for a configuration choice:
///
/// - **Could the directory be read?** Always fatal. An `Err` here used to become
///   `Ok(empty)` on the `--secondary` path, so a permission change left the
///   server up, listening, and answering REFUSED for every name it is
///   authoritative for.
/// - **Did every zone file parse?** Fatal unless `--allow-partial-load`. See
///   [`enumerate_zone_files`].
/// - **Is the directory empty?** Fatal *except* when replicating. A secondary's
///   first start has nothing on disk yet, and refusing to run until a zone
///   arrives would mean it never could — while for a primary an empty
///   `--zone-dir` is a typo in the path, and serving nothing is not what was
///   asked for.
///
/// The emptiness check lives here rather than in `enumerate_zone_files` because
/// only this function knows which of its callers is a secondary.
async fn load_zones_from_source(
    source: &ZoneSource,
    replicating: bool,
    allow_partial: bool,
) -> Result<HashMap<String, Zone>, Box<dyn std::error::Error>> {
    match source {
        ZoneSource::SingleFile(path) => {
            // Path-aware, so a `$INCLUDE` in the file resolves next to it rather
            // than against whatever directory the daemon happens to run in.
            let zone_origin = extract_zone_origin_from_path(path);
            let zone = parse_zone_file_at(Path::new(path), &zone_origin)?;
            let mut map = HashMap::new();
            map.insert(zone.origin().to_string(), zone);
            println!("Loaded zone from {}", path);
            Ok(map)
        }
        ZoneSource::Directory(dir) => {
            let zones = enumerate_zone_files(dir, allow_partial)?;
            if zones.is_empty() && !replicating {
                return Err(Box::from(format!(
                    "No .zone files found in directory: {dir}"
                )));
            }
            Ok(zones)
        }
    }
}

/// Extract zone origin from zone file path
/// Example: "example.com.zone" -> "example.com."
fn extract_zone_origin_from_path(path: &str) -> String {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("zone");
    
    // Remove .zone extension if present
    let origin = if let Some(stripped) = file_name.strip_suffix(".zone") {
        stripped
    } else {
        file_name
    };
    
    // Ensure it ends with a dot
    if origin.ends_with('.') {
        origin.to_string()
    } else {
        format!("{}.", origin)
    }
}

/// Enumerate all .zone files in a directory and load them
fn enumerate_zone_files(
    dir: &str,
    allow_partial: bool,
) -> Result<HashMap<String, Zone>, Box<dyn std::error::Error>> {
    let mut zones = HashMap::new();
    let mut failures: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("zone") {
            let path_str = path.to_string_lossy();
            let zone_origin = extract_zone_origin_from_path(&path_str);
            match parse_zone_file_at(&path, &zone_origin) {
                Ok(zone) => {
                    println!("Loaded zone from {}", path_str);
                    zones.insert(zone.origin().to_string(), zone);
                }
                Err(e) => failures.push(format!("{path_str}: {e}")),
            }
        }
    }

    // Every file, then the verdict — rather than stopping at the first failure,
    // because an operator fixing a deploy wants the whole list and not one typo
    // per restart.
    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("Error loading zone file {failure}");
        }
        if !allow_partial {
            // One line, because `main` returning an `Err` prints it with `{:?}`
            // and a multi-line message comes out with the newlines escaped. The
            // detail is on stderr just above, where it is readable.
            return Err(Box::from(format!(
                "{} of {} zone files in {dir} failed to load (listed above). Refusing to \
                 serve a partial set; pass --allow-partial-load to serve the {} that did.",
                failures.len(),
                failures.len() + zones.len(),
                zones.len(),
            )));
        }
        eprintln!(
            "--allow-partial-load: serving {} zones, {} failed and will answer REFUSED",
            zones.len(),
            failures.len()
        );
    }

    println!("Loaded {} zones from directory {}", zones.len(), dir);
    Ok(zones)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdns::{QueryClass, QuerySection};

    /// A query as it arrives on the wire, EDNS and all.
    fn query(qname: &str, qtype: u16, dnssec_ok: bool) -> DnsMessage {
        let mut msg = DnsMessage {
            id: 1,
            response: false,
            opcode: OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: qname.to_string(),
                qtype,
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let mut edns = Edns::with_payload_size(4096);
        edns.do_bit = dnssec_ok;
        msg.set_edns(edns).expect("set edns");
        msg
    }

    #[test]
    fn test_validate_cli_args_valid() {
        // Test CLI argument validation with valid args
        let result = validate_cli_args("0.0.0.0", 53);
        assert!(result.is_ok(), "Valid host and port should pass validation");
    }

    #[test]
    fn test_validate_cli_args_invalid_port_too_high() {
        // Test CLI argument validation with port > 65535
        // Since port is u16, we can only test with maximum valid value
        // This test documents the port range constraint
        let result = validate_cli_args("0.0.0.0", 65535);
        assert!(result.is_ok(), "Max port (65535) should pass validation");
    }

    #[test]
    fn test_validate_cli_args_invalid_port_zero() {
        // Test CLI argument validation with port 0
        let result = validate_cli_args("0.0.0.0", 0);
        assert!(result.is_err(), "Port 0 should fail validation");
    }

    #[test]
    fn test_validate_cli_args_localhost() {
        // Test CLI argument validation with localhost (valid for local dev)
        let result = validate_cli_args("127.0.0.1", 5353);
        assert!(result.is_ok(), "Localhost with custom port should pass validation");
    }

    #[test]
    fn test_validate_cli_args_custom_host() {
        // Test CLI argument validation with custom host
        let result = validate_cli_args("192.168.1.1", 8053);
        assert!(result.is_ok(), "Custom host and port should pass validation");
    }

    #[test]
    fn test_validate_cli_args_ipv6() {
        // Test CLI argument validation with IPv6 address (without brackets for validation)
        let result = validate_cli_args("::1", 53);
        assert!(result.is_ok(), "IPv6 address should pass validation");
    }

    #[test]
    fn test_extract_zone_origin_with_extension() {
        // Test zone origin extraction from filename with .zone extension
        let origin = extract_zone_origin_from_path("example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_with_path() {
        // Test zone origin extraction from full path
        let origin = extract_zone_origin_from_path("/etc/dns/example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_already_dotted() {
        // Test zone origin extraction when filename already has trailing dot
        let origin = extract_zone_origin_from_path("example.com..zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_no_extension() {
        // Test zone origin extraction from filename without .zone extension
        let origin = extract_zone_origin_from_path("example.com");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_deep_path() {
        // Test zone origin extraction from deep directory path
        let origin = extract_zone_origin_from_path("/var/lib/dns/zones/example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_validate_zone_source_file_present() {
        // Test zone source validation error when file doesn't exist
        // This documents that validate_zone_source checks file existence
        let result = validate_zone_source(Some("nonexistent.zone".to_string()), None, false);
        assert!(result.is_err(), "Non-existent file should fail validation");
    }

    #[test]
    fn test_validate_zone_source_dir_present() {
        // Test zone source validation error when directory doesn't exist
        // This documents that validate_zone_source checks directory existence
        let result = validate_zone_source(None, Some("/nonexistent/path".to_string()), false);
        assert!(result.is_err(), "Non-existent directory should fail validation");
    }

    #[test]
    fn test_validate_zone_source_both_present_error() {
        // Test zone source validation rejects when both file and dir provided
        let result = validate_zone_source(Some("test.zone".to_string()), Some("/etc/dns".to_string()), false);
        assert!(result.is_err(), "Should reject when both file and dir specified");
    }

    #[test]
    fn test_validate_zone_source_neither_present_error() {
        // Test zone source validation rejects when neither file nor dir provided
        let result = validate_zone_source(None, None, false);
        assert!(result.is_err(), "Should reject when neither file nor dir specified");
    }

    // -----------------------------------------------------------------
    // The secondary role
    // -----------------------------------------------------------------

    /// A transferred zone has to be written somewhere, and one file is not a
    /// place to put zones whose names we may not have seen yet.
    #[test]
    fn test_secondary_requires_a_zone_directory() {
        let Err(err) = validate_zone_source(Some("test.zone".to_string()), None, true) else {
            panic!("--secondary with only --zone-file should be refused");
        };
        assert!(err.to_string().contains("--zone-dir"), "got: {err}");
    }

    #[test]
    fn test_secondary_specs_are_parsed_or_refused() {
        let specs = parse_secondary_specs(&[
            "example.com@127.0.0.1:5353".to_string(),
            "  ".to_string(), // an empty repetition is not a zone
        ])
        .expect("parse");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].zone, "example.com.");

        let err = parse_secondary_specs(&["nonsense".to_string()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("--secondary"), "the error names the flag: {err}");
    }

    /// A primary on a loopback port, answering with `rdnsd`'s own AXFR path.
    ///
    /// Deliberately the real thing rather than a stub: `Server::serve_connection`
    /// is what a live `rdnsd` answers a transfer with, ACL and all, so what this
    /// exercises is the two halves of this codebase against each other rather
    /// than the secondary against a convenient fiction.
    async fn spawn_primary(zone_text: &str) -> SocketAddr {
        spawn_primary_with_acl(zone_text, &["127.0.0.1".to_string()]).await
    }

    /// A primary serving `new_text` that remembers the step from `old_text` —
    /// what a real one holds after a reload, and what lets it answer an IXFR.
    async fn spawn_primary_with_history(old_text: &str, new_text: &str) -> SocketAddr {
        let old = rdns::zone::parse_zone_file(old_text, "example.com.").expect("parse the old zone");
        let new = rdns::zone::parse_zone_file(new_text, "example.com.").expect("parse the new zone");
        let mut log = DeltaLog::new();
        log.note_change(Some(&old), &new);
        spawn_primary_inner(new, &["127.0.0.1".to_string()], log).await
    }

    async fn spawn_primary_with_acl(zone_text: &str, acl: &[String]) -> SocketAddr {
        let zone = rdns::zone::parse_zone_file(zone_text, "example.com.").expect("parse the zone");
        spawn_primary_inner(zone, acl, DeltaLog::new()).await
    }

    async fn spawn_primary_inner(zone: Zone, acl: &[String], log: DeltaLog) -> SocketAddr {
        let mut zones = HashMap::new();
        zones.insert(zone.origin().to_string(), zone);

        let server = Arc::new(Server {
            zone_map: Arc::new(RwLock::new(zones)),
            rate_limiter: Arc::new(RateLimiter::with_defaults()),
            validator: Arc::new(RequestValidator::with_defaults()),
            logger: Arc::new(QueryLogger::new()),
            metrics: Arc::new(DnsMetrics::new()),
            transfer_acl: Arc::new(TransferAcl::parse(acl).expect("acl")),
            tsig_keys: Arc::new(TsigKeyring::new(Vec::new())),
            response_limiter: Arc::new(ResponseLimiter::disabled()),
            secondaries: Arc::new(HashMap::new()),
            deltas: Arc::new(RwLock::new(log)),
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                tokio::spawn(server.clone().serve_connection(stream, peer));
            }
        });
        addr
    }

    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("rdnsd-secondary-{tag}-{unique}"));
            std::fs::create_dir_all(&dir).expect("scratch dir");
            ScratchDir(dir)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The replication context a refresh runs in, over a scratch directory.
    fn replication(dir: &ScratchDir, notify_targets: Vec<SocketAddr>) -> Replication {
        Replication {
            zone_map: Arc::new(RwLock::new(HashMap::new())),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            state: Arc::new(Mutex::new(StateFile::load(&state_file_path(&dir.0)))),
            zone_dir: dir.0.clone(),
            notify_targets,
        }
    }

    fn zone_text(serial: u32) -> String {
        format!(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. {serial} 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.2\n"
        )
    }

    /// The whole of step 3 in one test: a zone this server has never seen is
    /// fetched, served, written down, and remembered.
    #[tokio::test]
    async fn test_a_secondary_fetches_serves_and_persists_a_zone() {
        let dir = ScratchDir::new("fetch");
        let master = spawn_primary(&zone_text(7)).await;
        let spec = MasterSpec {
            zone: "example.com.".to_string(),
            master,
            key_name: None,
        };
        let r = replication(&dir, Vec::new());

        let outcome = refresh_once(&spec, None, &r)
            .await
            .expect("refresh");
        assert!(outcome.contains("transferred serial 7"), "got: {outcome}");

        // Served from memory...
        let zones = r.zone_map.read().await;
        let held = zones.get("example.com.").expect("the zone is now served");
        assert_eq!(held.serial(), Some(7));
        assert_eq!(held.query("www.example.com.", record_types::A).len(), 1);
        drop(zones);

        // ...written to disk, in the form the ordinary load path reads...
        let path = zone_file_path(&dir.0, "example.com.");
        let reloaded = parse_zone_file_at(&path, "example.com.").expect("reload from disk");
        assert_eq!(reloaded.serial(), Some(7));
        assert_eq!(reloaded.records().len(), 4);

        // ...and remembered, so a restart knows when contact was last made.
        let entry = r
            .state
            .lock()
            .unwrap()
            .get("example.com.", master)
            .cloned()
            .expect("state recorded");
        assert_eq!(entry.serial, 7);
        assert!(entry.refreshed_at > 0);
    }

    /// The serial comparison is the point of the SOA probe: an unchanged zone
    /// must not be transferred again, or every refresh interval would move the
    /// whole zone for nothing.
    #[tokio::test]
    async fn test_an_unchanged_serial_is_not_transferred_again() {
        let dir = ScratchDir::new("unchanged");
        let master = spawn_primary(&zone_text(7)).await;
        let spec = MasterSpec {
            zone: "example.com.".to_string(),
            master,
            key_name: None,
        };
        let r = replication(&dir, Vec::new());

        refresh_once(&spec, None, &r)
            .await
            .expect("first refresh");
        let second = refresh_once(&spec, None, &r)
            .await
            .expect("second refresh");

        assert!(second.contains("current"), "got: {second}");
        assert_eq!(
            r.zone_map.read().await.get("example.com.").unwrap().serial(),
            Some(7)
        );
    }

    /// And a serial that moved forward *is* transferred, replacing the zone
    /// wholesale rather than merging into it.
    #[tokio::test]
    async fn test_a_bumped_serial_replaces_the_zone() {
        let dir = ScratchDir::new("bumped");
        let spec_zone = "example.com.".to_string();
        let r = replication(&dir, Vec::new());

        let old = spawn_primary(&zone_text(7)).await;
        refresh_once(
            &MasterSpec { zone: spec_zone.clone(), master: old, key_name: None },
            None,
            &r,
        )
        .await
        .expect("first");

        // A primary whose zone has moved on — and lost a record, which is what
        // proves the zone is replaced rather than added to.
        let new = spawn_primary(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n",
        )
        .await;
        let outcome = refresh_once(
            &MasterSpec { zone: spec_zone, master: new, key_name: None },
            None,
            &r,
        )
        .await
        .expect("second");

        assert!(outcome.contains("serial 7 -> 8"), "got: {outcome}");
        let zones = r.zone_map.read().await;
        let held = zones.get("example.com.").unwrap();
        assert_eq!(held.serial(), Some(8));
        assert!(
            held.query("www.example.com.", record_types::A).is_empty(),
            "a record the new zone does not have must be gone, not merged"
        );
    }

    /// EXPIRE is the timer with teeth: out of contact past it, the zone stops
    /// being served rather than being answered for with stale data and AA set.
    #[tokio::test]
    async fn test_a_zone_out_of_contact_past_expire_is_withdrawn() {
        let dir = ScratchDir::new("expire");
        let master = "127.0.0.1:1".parse().expect("an address nothing answers on");
        let spec = MasterSpec {
            zone: "example.com.".to_string(),
            master,
            key_name: None,
        };

        let zone = rdns::zone::parse_zone_file(&zone_text(7), "example.com.").expect("zone");
        let timers = RefreshTimers::from_zone(&zone).expect("timers");
        let mut zones = HashMap::new();
        zones.insert(zone.origin().to_string(), zone);
        let zone_map = Arc::new(RwLock::new(zones));

        let mut state_file = StateFile::load(&state_file_path(&dir.0));
        // Contact was made, a very long time ago.
        state_file
            .record(TransferState {
                zone: "example.com.".to_string(),
                serial: 7,
                refreshed_at: current_unix_timestamp() - timers.expire - 1,
                master,
            })
            .expect("record");
        let state = Arc::new(Mutex::new(state_file));

        let r = Replication {
            zone_map: zone_map.clone(),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            state: state.clone(),
            zone_dir: dir.0.clone(),
            notify_targets: Vec::new(),
        };
        expire_if_out_of_contact(&spec, &r, current_unix_timestamp(), timers).await;
        assert!(
            zone_map.read().await.is_empty(),
            "an expired zone is no longer served"
        );

        // And the state line survives, so a restart still knows it is expired
        // rather than reading "nothing known" as "fetch and serve".
        assert!(state.lock().unwrap().get("example.com.", master).is_some());
    }

    /// Within EXPIRE, a failure to reach the master changes nothing: that is the
    /// whole point of having three timers rather than one.
    #[tokio::test]
    async fn test_a_recent_failure_does_not_withdraw_the_zone() {
        let dir = ScratchDir::new("still-good");
        let master = "127.0.0.1:1".parse().unwrap();
        let spec = MasterSpec {
            zone: "example.com.".to_string(),
            master,
            key_name: None,
        };

        let zone = rdns::zone::parse_zone_file(&zone_text(7), "example.com.").expect("zone");
        let timers = RefreshTimers::from_zone(&zone).expect("timers");
        let mut zones = HashMap::new();
        zones.insert(zone.origin().to_string(), zone);
        let zone_map = Arc::new(RwLock::new(zones));

        let mut state_file = StateFile::load(&state_file_path(&dir.0));
        state_file
            .record(TransferState {
                zone: "example.com.".to_string(),
                serial: 7,
                refreshed_at: current_unix_timestamp() - 60,
                master,
            })
            .expect("record");
        let state = Arc::new(Mutex::new(state_file));

        let r = Replication {
            zone_map: zone_map.clone(),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            state: state.clone(),
            zone_dir: dir.0.clone(),
            notify_targets: Vec::new(),
        };
        expire_if_out_of_contact(&spec, &r, current_unix_timestamp(), timers).await;
        assert_eq!(zone_map.read().await.len(), 1, "still served");
    }

    /// A refresh against a master that remembers the change moves only the
    /// difference — and lands on the same zone a full transfer would have.
    ///
    /// The equality is the assertion that matters: an incremental transfer that
    /// produces a *nearly* right zone is the failure mode this whole path has,
    /// and no serial comparison afterwards would ever notice it.
    #[tokio::test]
    async fn test_a_refresh_takes_the_increment_when_the_master_has_one() {
        let dir = ScratchDir::new("ixfr-in");
        let old_text = zone_text(7);
        let new_text = "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.250\n\
             extra IN TXT \"added in version 8\"\n";

        let r = replication(&dir, Vec::new());

        // Start from version 7, fetched in full because we hold nothing yet.
        let first = spawn_primary(&old_text).await;
        let spec = |master| MasterSpec {
            zone: "example.com.".to_string(),
            master,
            key_name: None,
        };
        refresh_once(&spec(first), None, &r)
            .await
            .expect("initial transfer");

        // Now a master that knows how to get from 7 to 8.
        let master = spawn_primary_with_history(&old_text, new_text).await;
        let outcome = refresh_once(&spec(master), None, &r)
            .await
            .expect("incremental refresh");
        assert!(
            outcome.contains("1 incremental step(s)"),
            "expected an increment, got: {outcome}"
        );

        let zones = r.zone_map.read().await;
        let held = zones.get("example.com.").expect("still served");
        assert_eq!(held.serial(), Some(8));
        assert_eq!(held.query("extra.example.com.", record_types::TXT).len(), 1);
        assert!(
            held.query("www.example.com.", record_types::A)
                .iter()
                .all(|r| r.rdata.parse().map(|p| matches!(p, rdns::ParsedRecord::A(a) if a.octets() == [192, 0, 2, 250])).unwrap_or(false)),
            "the old address must be gone, not merged"
        );

        // Record for record, the zone the master serves.
        let expected = rdns::zone::parse_zone_file(new_text, "example.com.").unwrap();
        let key = |z: &Zone| {
            let mut rows: Vec<_> = z
                .records()
                .iter()
                .map(|r| (z.normalize_name(&r.name).to_lowercase(), r.ttl, r.rdata.clone()))
                .collect();
            rows.sort_by_key(|r| (r.0.clone(), r.2.rtype));
            rows
        };
        assert_eq!(key(held), key(&expected), "the increment reproduced the zone");
    }

    /// A secondary that takes a transfer tells its own secondaries at once.
    ///
    /// Without this, only a *primary* ever announces — at startup and on SIGHUP —
    /// so the first level of a replication tree updates immediately and every
    /// level below it waits out a refresh timer. RFC 1996 §3.2's "master" is
    /// whoever serves the zone to someone, which a secondary in the middle is.
    #[tokio::test]
    async fn test_a_secondary_announces_what_it_transferred() {
        let dir = ScratchDir::new("announce");
        let master = spawn_primary(&zone_text(11)).await;

        // A socket standing in for a downstream secondary, so the NOTIFY is
        // caught on the wire rather than inferred from a log line.
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let r = replication(&dir, vec![target]);
        let spec = MasterSpec {
            zone: "example.com.".to_string(),
            master,
            key_name: None,
        };

        refresh_once(&spec, None, &r)
            .await
            .expect("transfer");

        let mut buf = vec![0u8; 4096];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(5), downstream.recv_from(&mut buf))
            .await
            .expect("a NOTIFY should arrive")
            .expect("recv");

        let msg = DnsMessage::try_from_bytes(&buf[..n]).expect("parse the NOTIFY");
        assert_eq!(msg.opcode, OpCode::Notify, "a NOTIFY, not a query");
        assert!(!msg.response);
        assert_eq!(
            notify::notified_zone(&msg).as_deref(),
            Some("example.com."),
            "for the zone that moved"
        );
        assert_eq!(
            notify::notified_serial(&msg),
            Some(11),
            "carrying the serial we just transferred, so the downstream \
             secondary need not ask"
        );
    }

    /// Nothing is announced when nothing moved: a refresh that confirms the
    /// serial is unchanged is not news, and telling anyone would cost them a
    /// pointless SOA probe every refresh interval.
    #[tokio::test]
    async fn test_an_unchanged_refresh_announces_nothing() {
        let dir = ScratchDir::new("announce-quiet");
        let master = spawn_primary(&zone_text(11)).await;
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let r = replication(&dir, vec![target]);
        let spec = MasterSpec {
            zone: "example.com.".to_string(),
            master,
            key_name: None,
        };

        // The first transfer announces; drain it.
        refresh_once(&spec, None, &r)
            .await
            .expect("transfer");
        let mut buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(5), downstream.recv_from(&mut buf))
            .await
            .expect("the first NOTIFY");

        // The second finds the same serial and must say nothing.
        let outcome = refresh_once(&spec, None, &r)
            .await
            .expect("second refresh");
        assert!(outcome.contains("current"), "got: {outcome}");
        assert!(
            tokio::time::timeout(Duration::from_millis(500), downstream.recv_from(&mut buf))
                .await
                .is_err(),
            "an unchanged zone is not news"
        );
    }

    /// A secondary that receives a change can answer an IXFR for it — which is
    /// what makes one of these an interior node of a replication tree rather than
    /// a leaf. The delta only exists if the swap recorded it, so this is really a
    /// test that the zone map and the delta log move together.
    #[tokio::test]
    async fn test_a_transferred_change_becomes_an_increment_we_can_serve() {
        let dir = ScratchDir::new("ixfr-out");
        let r = replication(&dir, Vec::new());
        let spec = |master| MasterSpec {
            zone: "example.com.".to_string(),
            master,
            key_name: None,
        };

        let first = spawn_primary(&zone_text(7)).await;
        refresh_once(&spec(first), None, &r)
            .await
            .expect("first transfer");
        assert_eq!(
            r.deltas.read().await.len("example.com."),
            0,
            "a first fetch has no previous version to differ from"
        );

        let second = spawn_primary(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.250\n",
        )
        .await;
        refresh_once(&spec(second), None, &r)
            .await
            .expect("second transfer");

        let log = r.deltas.read().await;
        assert_eq!(log.len("example.com."), 1, "the change was recorded");
        let chain = log.chain_from("example.com.", 7).expect("a chain from 7");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].to_serial, 8);
        // www's address changed: one deletion, one addition.
        assert_eq!(chain[0].deleted.len(), 1);
        assert_eq!(chain[0].added.len(), 1);
    }

    /// A reload is a version step too, and a zone that leaves the configuration
    /// takes its history with it — we cannot offer increments of a zone we no
    /// longer serve.
    #[tokio::test]
    async fn test_a_reload_records_its_changes_and_forgets_removed_zones() {
        let zone_map = Arc::new(RwLock::new(HashMap::new()));
        let deltas = Arc::new(RwLock::new(DeltaLog::new()));
        let parse = |text: &str, origin: &str| {
            rdns::zone::parse_zone_file(text, origin).expect("zone should parse")
        };

        let v7 = parse(&zone_text(7), "example.com.");
        let other = parse(
            "@ IN SOA ns1.other.test. admin.other.test. 1 3600 1800 604800 86400\n\
             @ IN NS ns1.other.test.\n",
            "other.test.",
        );
        let mut initial = HashMap::new();
        initial.insert(v7.origin().to_string(), v7);
        initial.insert(other.origin().to_string(), other);
        install_all_zones(&zone_map, &deltas, initial).await;
        assert!(deltas.read().await.is_empty(), "nothing to differ from yet");

        // example.com. moves on; other.test. is dropped from the configuration.
        let v8 = parse(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.222\n",
            "example.com.",
        );
        let mut reloaded = HashMap::new();
        reloaded.insert(v8.origin().to_string(), v8);
        install_all_zones(&zone_map, &deltas, reloaded).await;

        let log = deltas.read().await;
        assert_eq!(log.len("example.com."), 1, "the reload is a version step");
        assert_eq!(log.len("other.test."), 0, "a zone we no longer serve");
        assert_eq!(zone_map.read().await.len(), 1);
    }

    /// An IXFR is gated by the same ACL as an AXFR, and it has to be: it may
    /// *answer* with the whole zone (RFC 1995 §4), so a policy that let it
    /// through would be no policy at all. The default is to refuse everyone, and
    /// this is the test that a new transfer type did not quietly escape it.
    #[tokio::test]
    async fn test_an_ixfr_is_refused_by_the_same_default_that_refuses_an_axfr() {
        let master = spawn_primary_with_acl(&zone_text(7), &[]).await;
        let spec = MasterSpec {
            zone: "example.com.".to_string(),
            master,
            key_name: None,
        };
        let dir = ScratchDir::new("refused");
        let r = replication(&dir, Vec::new());

        // The AXFR our own client makes is refused, which is the baseline.
        let err = refresh_once(&spec, None, &r).await.unwrap_err();
        assert!(err.contains("Refused"), "got: {err}");

        // And so is an IXFR, over the same connection path.
        let request = {
            let mut msg = rdns::xfr::axfr_request("example.com.", 0x33);
            msg.queries[0].qtype = record_types::IXFR;
            msg
        };
        let mut buf = vec![0u8; 512];
        let n = request.to_bytes(&mut buf).expect("serialize");
        let mut framed = (n as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&buf[..n]);

        let mut stream = TcpStream::connect(master).await.expect("connect");
        stream.write_all(&framed).await.expect("send");
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.expect("length");
        let mut packet = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut packet).await.expect("reply");

        let reply = DnsMessage::try_from_bytes(&packet).expect("parse");
        assert_eq!(reply.rcode, ResponseCode::Refused);
        assert!(reply.answers.is_empty(), "a refusal carries no zone");
    }

    // -----------------------------------------------------------------------
    // Loading a directory of zones: three questions, three answers
    // -----------------------------------------------------------------------

    mod loading {
        use super::*;

        const GOOD: &str = "@ IN SOA ns1.example.com. admin.example.com. \
                            1 3600 600 604800 300\n@ IN NS ns1.example.com.\n";
        const BROKEN: &str = "@ IN SOA ns1.broken.test. admin.broken.test. \
                              1 3600 600 604800 300\nwww IN A not-an-address\n";

        fn dir_with(tag: &str, files: &[(&str, &str)]) -> ScratchDir {
            let dir = ScratchDir::new(tag);
            for (name, text) in files {
                std::fs::write(dir.0.join(name), text).expect("write zone");
            }
            dir
        }

        /// One bad file out of three used to be a line on stderr, exit code 0, and
        /// that zone answering **REFUSED** — indistinguishable from a zone nobody
        /// configured. It also defeated the all-or-nothing invariant
        /// `Reloading::load`'s own doc comment claims, because `install_all_zones`
        /// then installed the survivors wholesale: a broken file plus a deploy
        /// SIGHUP took a *previously working* zone off the air.
        #[tokio::test]
        async fn a_zone_file_that_fails_to_parse_fails_the_load() {
            let dir = dir_with(
                "partial",
                &[
                    ("example.com.zone", GOOD),
                    ("other.test.zone", GOOD),
                    ("broken.test.zone", BROKEN),
                ],
            );
            let source = ZoneSource::Directory(dir.0.to_string_lossy().to_string());

            let err = load_zones_from_source(&source, false, false)
                .await
                .expect_err("a broken zone file must not pass for a configuration choice")
                .to_string();
            assert!(
                err.contains("1 of 3"),
                "say how many of how many, so the scale is visible: {err}"
            );
            assert!(
                err.contains("--allow-partial-load"),
                "and say what to do about it: {err}"
            );
        }

        /// The escape hatch, because the behaviour is defensible when the
        /// alternative is worse — 39 of 40 zones beats none. It just has to be a
        /// decision rather than what happens when nobody looked.
        #[tokio::test]
        async fn allow_partial_load_serves_what_parsed() {
            let dir = dir_with(
                "partial-ok",
                &[("example.com.zone", GOOD), ("broken.test.zone", BROKEN)],
            );
            let source = ZoneSource::Directory(dir.0.to_string_lossy().to_string());

            let zones = load_zones_from_source(&source, false, true)
                .await
                .expect("the flag is an explicit choice to serve a partial set");
            assert_eq!(zones.len(), 1);
            assert!(zones.contains_key("example.com."));
        }

        /// A secondary's first start has nothing on disk yet, and refusing to run
        /// until a zone arrives would mean it never could.
        ///
        /// **This is a regression test for a fix, not for the original bug.**
        /// Removing the `unwrap_or_default()` that turned an unreadable directory
        /// into `Ok(empty)` also removed the only thing making an *empty*
        /// directory work, because `enumerate_zone_files` returned
        /// `Err("No .zone files found")` for one — and the commit that removed it
        /// claimed the opposite. Nothing caught it, because nothing tested a
        /// secondary starting from an empty directory. The emptiness check now
        /// lives in `load_zones_from_source`, which is the only place that knows
        /// whether the caller is a secondary.
        #[tokio::test]
        async fn a_secondary_may_start_with_an_empty_zone_directory() {
            let dir = dir_with("empty-secondary", &[]);
            let source = ZoneSource::Directory(dir.0.to_string_lossy().to_string());

            let zones = load_zones_from_source(&source, true, false)
                .await
                .expect("a secondary starts before its first transfer");
            assert!(zones.is_empty());

            // A primary with an empty --zone-dir is a typo in the path, and
            // serving nothing is not what was asked for.
            assert!(load_zones_from_source(&source, false, false).await.is_err());
        }

        /// The zone a secondary replicates, with an EXPIRE of one hour so the
        /// arithmetic in the tests below is legible.
        const REPLICATED: &str = "@ IN SOA ns1.example.com. admin.example.com. \
                                  7 3600 600 3600 300\n@ IN NS ns1.example.com.\n";

        /// A secondary mid-life: a zone dir, the spec it replicates under, and
        /// the two maps a withdrawal touches.
        struct Replica {
            dir: ScratchDir,
            specs: Vec<MasterSpec>,
            zone_map: Arc<RwLock<HashMap<String, Zone>>>,
            deltas: Arc<RwLock<DeltaLog>>,
        }

        fn replicated_setup(tag: &str) -> Replica {
            let dir = ScratchDir::new(tag);
            let zone = rdns::zone::parse_zone_file(REPLICATED, "example.com.").expect("zone");
            let mut zones = HashMap::new();
            zones.insert(zone.origin().to_string(), zone);
            let specs = vec![MasterSpec {
                zone: "example.com.".to_string(),
                master: "192.0.2.1:53".parse().unwrap(),
                key_name: None,
            }];
            Replica {
                dir,
                specs,
                zone_map: Arc::new(RwLock::new(zones)),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
            }
        }

        fn record_contact(dir: &ScratchDir, master: &str, refreshed_at: u64) {
            let mut state = StateFile::load(&state_file_path(&dir.0));
            state
                .record(TransferState {
                    zone: "example.com.".to_string(),
                    serial: 7,
                    refreshed_at,
                    master: master.parse().unwrap(),
                })
                .expect("write the sidecar");
        }

        /// Expiry that lasts only until the next deploy is not expiry.
        ///
        /// `expire_stale_zones_at_startup` ran from `main` and nowhere else, while
        /// `Reloading::load` re-reads every `.zone` file from disk without
        /// consulting the sidecar. A zone correctly withdrawn because its primary
        /// had been unreachable for a week came straight back on SIGHUP and was
        /// served **with AA set** — which is precisely the "permanently wrong
        /// answers nobody can see are wrong" the withdrawal code's own comment
        /// says it exists to prevent.
        #[tokio::test]
        async fn a_reload_does_not_resurrect_a_zone_that_expired() {
            let Replica { dir, specs, zone_map, deltas } = replicated_setup("expire-reload");
            // Last contact two hours ago, against an EXPIRE of one.
            record_contact(&dir, "192.0.2.1:53", current_unix_timestamp() - 7200);

            withdraw_unvouched_zones(&specs, &zone_map, &deltas, &dir.0).await;
            assert!(
                zone_map.read().await.is_empty(),
                "out of contact past EXPIRE is not ours to answer for"
            );

            // Now the reload: the file is still on disk, so it comes back.
            let zone = rdns::zone::parse_zone_file(REPLICATED, "example.com.").unwrap();
            let mut reloaded = HashMap::new();
            reloaded.insert(zone.origin().to_string(), zone);
            install_all_zones(&zone_map, &deltas, reloaded).await;
            assert_eq!(zone_map.read().await.len(), 1, "a reload re-reads the file");

            // ...and must be withdrawn again, which is the whole finding.
            withdraw_unvouched_zones(&specs, &zone_map, &deltas, &dir.0).await;
            assert!(
                zone_map.read().await.is_empty(),
                "a SIGHUP is not new contact with the master"
            );
        }

        /// The other half: no record of contact at all.
        ///
        /// `StateFile::load` returns empty rather than failing — right for a
        /// cache, wrong for expiry, because forgetting the last-contact time *is*
        /// the difference between withdrawn and served. A missing or unreadable
        /// sidecar used to mean the stale copy on disk was served authoritatively
        /// from a cold start. Unknown age has to read as "do not serve": the zone
        /// comes back at the first successful transfer, which is what makes it
        /// ours to answer for in the first place.
        #[tokio::test]
        async fn a_zone_with_no_record_of_transfer_is_not_served() {
            let Replica { dir, specs, zone_map, deltas } = replicated_setup("expire-nostate");
            assert!(!state_file_path(&dir.0).exists(), "no sidecar at all");

            withdraw_unvouched_zones(&specs, &zone_map, &deltas, &dir.0).await;
            assert!(zone_map.read().await.is_empty());
        }

        /// A sidecar entry for a *different* master is not evidence about this
        /// one, and lands in the same place.
        #[tokio::test]
        async fn a_record_for_another_master_does_not_vouch_for_this_one() {
            let Replica { dir, specs, zone_map, deltas } = replicated_setup("expire-othermaster");
            record_contact(&dir, "192.0.2.99:53", current_unix_timestamp());

            withdraw_unvouched_zones(&specs, &zone_map, &deltas, &dir.0).await;
            assert!(zone_map.read().await.is_empty());
        }

        /// And the control, because the check has to be narrow: a zone in contact
        /// keeps being served, reload or no reload.
        #[tokio::test]
        async fn a_zone_in_contact_with_its_master_keeps_being_served() {
            let Replica { dir, specs, zone_map, deltas } = replicated_setup("expire-fresh");
            record_contact(&dir, "192.0.2.1:53", current_unix_timestamp());

            withdraw_unvouched_zones(&specs, &zone_map, &deltas, &dir.0).await;
            assert_eq!(zone_map.read().await.len(), 1);
        }

        /// A directory that cannot be read is fatal either way — this is the
        /// original #9c finding, and `--allow-partial-load` must not weaken it.
        /// "Some files failed to parse" and "the directory is not there" are
        /// different questions, and only the first one has a flag.
        #[tokio::test]
        async fn an_unreadable_directory_is_fatal_even_with_partial_load() {
            let missing = ZoneSource::Directory("no-such-directory-anywhere".to_string());
            for allow_partial in [false, true] {
                assert!(
                    load_zones_from_source(&missing, true, allow_partial)
                        .await
                        .is_err(),
                    "allow_partial={allow_partial}: an I/O error is not a parse failure"
                );
            }
        }
    }

    /// A *response* arriving at the server port is dropped, not answered.
    ///
    /// `RequestValidator` deliberately accepts QR=1 — it is used on both
    /// directions of the wire — so nothing between the socket and the zone lookup
    /// tested it, and `make_response` would happily build a reply to a reply. Two
    /// servers pointed at each other, or one spoofed datagram with a forged
    /// source, is then a packet loop that neither end can see is one.
    #[tokio::test]
    async fn a_response_sent_to_the_server_port_is_dropped() {
        let zone = rdns::zone::parse_zone_file(
            "@ IN SOA ns1.example.com. admin.example.com. 1 3600 600 604800 300\n\
             @ IN NS ns1.example.com.\n\
             ns1 IN A 192.0.2.1\n",
            "example.com.",
        )
        .expect("parse the zone");
        let mut zones = HashMap::new();
        zones.insert(zone.origin().to_string(), zone);
        let server = Server {
            zone_map: Arc::new(RwLock::new(zones)),
            rate_limiter: Arc::new(RateLimiter::with_defaults()),
            validator: Arc::new(RequestValidator::with_defaults()),
            logger: Arc::new(QueryLogger::new()),
            metrics: Arc::new(DnsMetrics::new()),
            transfer_acl: Arc::new(TransferAcl::parse(&[]).expect("acl")),
            tsig_keys: Arc::new(TsigKeyring::new(Vec::new())),
            response_limiter: Arc::new(ResponseLimiter::disabled()),
            secondaries: Arc::new(HashMap::new()),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
        };
        let peer: SocketAddr = "192.0.2.9:5353".parse().unwrap();

        let wire = |msg: &DnsMessage| {
            let mut buf = vec![0u8; 512];
            let n = msg.to_bytes(&mut buf).expect("serialize");
            buf.truncate(n);
            buf
        };

        // The control: the same question, asked as a question, is answered.
        let mut question = query("ns1.example.com.", record_types::A, false);
        assert!(
            !server.answer(&wire(&question), peer).await.is_empty(),
            "a real query must still be answered — the check has to be narrow"
        );

        // The same bytes with QR set are a response, and get nothing back.
        question.response = true;
        assert!(
            server.answer(&wire(&question), peer).await.is_empty(),
            "a response is not a question, and replying to one is a packet loop"
        );
    }

    /// A NOTIFY is acted on when it comes from a master of a zone we replicate,
    /// refused when it does not, and NOTAUTH for anything we are not a secondary
    /// for — three different answers to three different situations.
    #[test]
    fn test_notify_is_answered_by_what_the_zone_is_to_us() {
        let wake = Arc::new(Notify::new());
        let mut registry = HashMap::new();
        registry.insert(
            "replicated.test.".to_string(),
            ReplicatedZone {
                masters: vec!["192.0.2.1".parse().unwrap()],
                wake: vec![wake.clone()],
            },
        );
        let secondaries: Secondaries = Arc::new(registry);

        let primary_zone =
            rdns::zone::parse_zone_file(&zone_text(1), "example.com.").expect("zone");
        let mut zones = HashMap::new();
        zones.insert(primary_zone.origin().to_string(), primary_zone);

        let from = |zone: &str, ip: &str| {
            let msg = notify::notify_request(zone, None, 1);
            let peer: SocketAddr = format!("{ip}:5353").parse().unwrap();
            notify_reply(&msg, &zones, &secondaries, peer).rcode
        };

        assert_eq!(
            from("replicated.test.", "192.0.2.1"),
            ResponseCode::Ok,
            "from its master: acted on"
        );
        assert_eq!(
            from("replicated.test.", "203.0.113.9"),
            ResponseCode::Refused,
            "from anywhere else: refused, because acting would cost us a transfer"
        );
        assert_eq!(
            from("example.com.", "192.0.2.1"),
            ResponseCode::NotAuthorized,
            "a zone we are the primary for: we are nobody's secondary for it"
        );
        assert_eq!(
            from("never-heard-of.test.", "192.0.2.1"),
            ResponseCode::NotAuthorized
        );
    }

    // -----------------------------------------------------------------------
    // RFC 1034 §4.3.2: the four cases an authoritative answer can be
    // -----------------------------------------------------------------------

    /// Three of the four cases were missing here, and the suite was green the
    /// whole time because it asserted what the code did. Each test below names
    /// the wire shape that used to go out.
    mod answer_path {
        use super::*;
        use rdns::zone::parse_zone_file;

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
"#;

        fn server() -> HashMap<String, Zone> {
            let zone = parse_zone_file(ZONE, "example.com.").expect("the test zone parses");
            let mut zones = HashMap::new();
            zones.insert(zone.origin().to_string(), zone);
            zones
        }

        fn ask(qname: &str, qtype: u16) -> DnsMessage {
            make_response(&query(qname, qtype, false), &server(), &DnsMetrics::new())
        }

        fn rdatas(records: &[ResourceRecord], rtype: u16) -> Vec<&ResourceRecord> {
            records.iter().filter(|r| r.rdata.rtype == rtype).collect()
        }

        /// The wire shape that used to go out for every CNAME in every zone this
        /// server loaded: an empty NOERROR with the SOA — "this name has no A
        /// record". `getaddrinfo` fails on it, and BIND and Unbound cache the
        /// NODATA and never follow the alias.
        #[test]
        fn a_cname_is_followed_to_its_target_in_the_same_zone() {
            let response = ask("www.example.com.", record_types::A);

            assert_eq!(response.rcode, ResponseCode::Ok);
            assert!(response.authoritive);
            let cnames = rdatas(&response.answers, record_types::CNAME);
            assert_eq!(cnames.len(), 1, "the alias itself comes first");
            assert_eq!(cnames[0].name, "www.example.com.");

            let addresses = rdatas(&response.answers, record_types::A);
            assert_eq!(addresses.len(), 1, "and the data it points at");
            assert_eq!(addresses[0].name, "host.example.com.");
            assert!(
                response.authorities.is_empty(),
                "an answer is not a negative answer and owes no SOA"
            );
        }

        /// A chain leaving the zone stops with what we hold. NXDOMAIN here would
        /// be an assertion about a name in somebody else's zone.
        #[test]
        fn a_cname_out_of_the_zone_stops_with_the_partial_chain() {
            let response = ask("away.example.com.", record_types::A);

            assert_eq!(response.rcode, ResponseCode::Ok, "not NXDOMAIN");
            assert_eq!(rdatas(&response.answers, record_types::CNAME).len(), 1);
            assert!(rdatas(&response.answers, record_types::A).is_empty());
        }

        /// A CNAME query is answered by the CNAME, not followed by it.
        #[test]
        fn a_cname_query_is_not_chased() {
            let response = ask("www.example.com.", record_types::CNAME);
            assert_eq!(response.answers.len(), 1);
            assert_eq!(response.answers[0].rdata.rtype, record_types::CNAME);
        }

        /// A broken zone must not hang the server. Two aliases pointing at each
        /// other terminate on the visited set, not on the hop limit.
        #[test]
        fn a_cname_loop_terminates() {
            let response = ask("loop1.example.com.", record_types::A);
            assert_eq!(response.rcode, ResponseCode::Ok);
            assert!(
                rdatas(&response.answers, record_types::CNAME).len() <= MAX_CNAME_HOPS,
                "the chain is bounded"
            );
        }

        /// The referral, and the header bit that makes it one. This used to be an
        /// NXDOMAIN with **AA=1**, so per RFC 8020 every resolver cached "the
        /// whole subtree does not exist" and the child zone was off the internet
        /// for the negative TTL.
        #[test]
        fn a_name_below_a_delegation_gets_a_referral_not_an_nxdomain() {
            let response = ask("anything.sub.example.com.", record_types::A);

            assert_eq!(response.rcode, ResponseCode::Ok, "a referral is not an error");
            assert!(
                !response.authoritive,
                "RFC 1035 §4.1.1: AA is clear on a referral — this is the bit that \
                 stopped the child zone resolving"
            );
            assert!(response.answers.is_empty());

            let ns = rdatas(&response.authorities, record_types::NS);
            assert_eq!(ns.len(), 2, "the child's NS RRset, in the authority section");
            assert!(ns.iter().all(|r| r.name == "sub.example.com."));
            assert!(
                rdatas(&response.authorities, record_types::SOA).is_empty(),
                "a referral carries no SOA — it is not a negative answer"
            );

            // In-bailiwick glue only: an address for `ns.other.test.` would be an
            // assertion about a zone we do not serve.
            let glue = rdatas(&response.additionals, record_types::A);
            assert_eq!(glue.len(), 1, "{:?}", response.additionals);
            assert_eq!(glue[0].name, "ns.sub.example.com.");
        }

        /// The wildcard at the apex must not answer for a name below the cut
        /// (RFC 4592 §2.2.1) — that name belongs to the child.
        #[test]
        fn the_delegation_wins_over_the_wildcard() {
            let response = ask("anything.sub.example.com.", record_types::A);
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
            let mut zones = HashMap::new();
            zones.insert(zone.origin().to_string(), zone);

            let response = make_response(
                &query("sub.example.com.", record_types::DS, false),
                &zones,
                &DnsMetrics::new(),
            );
            assert_eq!(rdatas(&response.answers, record_types::DS).len(), 1);
            assert!(response.authoritive, "the DS is the parent's own data");

            // Anything else at the same name is a referral.
            let ns = make_response(
                &query("sub.example.com.", record_types::NS, false),
                &zones,
                &DnsMetrics::new(),
            );
            assert!(!ns.authoritive);
            assert!(ns.answers.is_empty());
        }

        /// RFC 4592 §3.3.2: synthesis reaches any depth, not one label.
        #[test]
        fn a_wildcard_answers_a_name_more_than_one_label_deep() {
            let response = ask("a.b.c.example.com.", record_types::A);
            assert_eq!(response.rcode, ResponseCode::Ok);
            let addresses = rdatas(&response.answers, record_types::A);
            assert_eq!(addresses.len(), 1);
            assert_eq!(addresses[0].name, "a.b.c.example.com.", "echoed as asked");
        }

        /// RFC 4592 §2.2.2: a name with descendants exists. NXDOMAIN here is the
        /// zone taking *its own* data offline, because an RFC 8020 resolver
        /// extends the denial down to `deep.a.b`.
        #[test]
        fn an_empty_non_terminal_is_nodata_not_nxdomain() {
            let response = ask("a.b.example.com.", record_types::TXT);
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
                let response = ask(qname, qtype);
                let soa = rdatas(&response.authorities, record_types::SOA);
                assert_eq!(soa.len(), 1, "{what}");
                assert_eq!(soa[0].ttl, 300, "{what}: capped at MINIMUM, not the $TTL");
            }
        }

        /// And the NXDOMAIN that is still an NXDOMAIN, so the fixes above did not
        /// turn every name into a hit: `x.a.b` is below an existing name, so the
        /// apex wildcard is not its source of synthesis and nothing answers.
        #[test]
        fn a_name_nothing_reaches_is_still_nxdomain() {
            let response = ask("x.a.b.example.com.", record_types::A);
            assert_eq!(response.rcode, ResponseCode::NoSuchDomain);
            assert!(response.authoritive, "we are authoritative for saying no");
            assert_eq!(rdatas(&response.authorities, record_types::SOA).len(), 1);
        }
    }

    // -----------------------------------------------------------------------
    // Signing, and answering a client that can read the result
    // -----------------------------------------------------------------------

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
        fn signed_server(nsec3: bool) -> (HashMap<String, Zone>, Vec<SigningKey>) {
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
            let mut zones = HashMap::new();
            zones.insert(zone.origin().to_string(), zone);
            (zones, keys)
        }

        fn keys_of(zones: &HashMap<String, Zone>) -> Vec<Dnskey> {
            let zone = &zones["example.com."];
            dnskeys_in(
                &zone
                    .query("example.com.", record_types::DNSKEY)
                    .into_iter()
                    .map(|r| ResourceRecord {
                        name: r.name.clone(),
                        class: r.class,
                        ttl: r.ttl,
                        rdata: r.rdata.clone(),
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

        fn signed_zones(text: &str, nsec3: bool) -> (HashMap<String, Zone>, Vec<SigningKey>) {
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
            let mut zones = HashMap::new();
            zones.insert(zone.origin().to_string(), zone);
            (zones, keys)
        }

        /// The failure this is the regression test for: **a signed zone with a
        /// wildcard SERVFAILed at every validator for every non-existent name two
        /// or more labels deep.** The synthesis reached one label, so a deeper
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
                    &query(qname, record_types::A, true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert_eq!(response.rcode, ResponseCode::Ok, "nsec3={nsec3}");
                let rdatas: Vec<RecordData> = response
                    .answers
                    .iter()
                    .filter(|r| r.rdata.rtype == record_types::A)
                    .map(|r| r.rdata.clone())
                    .collect();
                assert_eq!(rdatas.len(), 1, "nsec3={nsec3}: no wildcard answer");

                let proof = verify_rrset(
                    &Rrset::new(qname, record_types::A, 1, &rdatas),
                    &rrsigs_in(&response.answers),
                    &keys_of(&zones),
                    "example.com.",
                    current_unix_timestamp(),
                );
                let RrsetProof::Verified {
                    wildcard: Some(wildcard),
                    ..
                } = proof
                else {
                    panic!("nsec3={nsec3}: expected a wildcard expansion, got {proof:?}");
                };
                assert_eq!(wildcard, "*.example.com.");

                // And the denial it owes: without it one captured answer is a
                // valid answer for every name the wildcard reaches
                // (RFC 4035 §3.1.3).
                let verdict = proves_wildcard_expansion(
                    qname,
                    &wildcard,
                    &nsecs_in(&response.authorities),
                    &nsec3s_in(&response.authorities),
                );
                assert!(
                    matches!(verdict, WildcardVerdict::Proved),
                    "nsec3={nsec3}: {verdict:?}"
                );
            }
        }

        /// A secure delegation hands down the DS and its signature, and the NS
        /// RRset goes out **unsigned** — it is the child's data (RFC 4035 §2.2).
        #[test]
        fn a_secure_referral_carries_the_ds_and_leaves_the_ns_rrset_unsigned() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(DELEGATING_ZONE, nsec3);
                let response = make_response(
                    &query("host.secure.example.com.", record_types::A, true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert!(!response.authoritive, "nsec3={nsec3}");
                let ds: Vec<RecordData> = response
                    .authorities
                    .iter()
                    .filter(|r| r.rdata.rtype == record_types::DS)
                    .map(|r| r.rdata.clone())
                    .collect();
                assert_eq!(ds.len(), 1, "nsec3={nsec3}: the DS is what continues the chain");

                let sigs = rrsigs_in(&response.authorities);
                let proof = verify_rrset(
                    &Rrset::new("secure.example.com.", record_types::DS, 1, &ds),
                    &sigs,
                    &keys_of(&zones),
                    "example.com.",
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
                    &query("host.plain.example.com.", record_types::A, true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert!(!response.authoritive, "nsec3={nsec3}");
                assert!(
                    !response
                        .authorities
                        .iter()
                        .any(|r| r.rdata.rtype == record_types::DS),
                    "nsec3={nsec3}: this child is not signed"
                );
                let denial = proves_no_ds(
                    "plain.example.com.",
                    &nsecs_in(&response.authorities),
                    &nsec3s_in(&response.authorities),
                );
                assert!(matches!(denial, Denial::Proved), "nsec3={nsec3}: {denial:?}");
            }
        }

        #[test]
        fn a_do_query_gets_an_answer_a_validator_accepts() {
            let (zones, _keys) = signed_server(false);
            let metrics = DnsMetrics::new();
            let response = make_response(
                &query("www.example.com.", record_types::A, true),
                &zones,
                &metrics,
            );

            // Judge it the way a client would: only what came back.
            let rdatas: Vec<RecordData> = response
                .answers
                .iter()
                .filter(|r| r.rdata.rtype == record_types::A)
                .map(|r| r.rdata.clone())
                .collect();
            let proof = verify_rrset(
                &Rrset::new("www.example.com.", record_types::A, 1, &rdatas),
                &rrsigs_in(&response.answers),
                &keys_of(&zones),
                "example.com.",
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
                    &query("gone.a.b.example.com.", record_types::A, true),
                    &zones,
                    &metrics,
                );
                assert_eq!(response.rcode, ResponseCode::NoSuchDomain);

                let denial = proves_nxdomain(
                    "gone.a.b.example.com.",
                    "example.com.",
                    &nsecs_in(&response.authorities),
                    &nsec3s_in(&response.authorities),
                );
                assert!(matches!(denial, Denial::Proved), "nsec3={nsec3}: {denial:?}");
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
                &query("www.example.com.", record_types::A, false),
                &zones,
                &metrics,
            );
            assert!(rrsigs_in(&answer.answers).is_empty());
            assert!(!answer.edns().unwrap().unwrap().do_bit);

            let denial = make_response(
                &query("nope.example.com.", record_types::A, false),
                &zones,
                &metrics,
            );
            assert!(nsecs_in(&denial.authorities).is_empty());
            // The SOA is still there: a negative answer has always carried one
            // (RFC 2308), signed zone or not.
            assert!(denial
                .authorities
                .iter()
                .any(|r| r.rdata.rtype == record_types::SOA));
        }

        #[test]
        fn the_do_bit_comes_back_set() {
            // RFC 3225 §3. Without it the client cannot tell an answer with no
            // DNSSEC records from a server that dropped them.
            let (zones, _keys) = signed_server(false);
            let metrics = DnsMetrics::new();
            let response = make_response(
                &query("www.example.com.", record_types::A, true),
                &zones,
                &metrics,
            );
            assert!(response.edns().unwrap().unwrap().do_bit);
        }

        #[test]
        fn an_unsigned_zone_answers_a_do_query_the_way_it_answers_any_other() {
            let mut zones = HashMap::new();
            let zone = parse_zone_file(SIGNED_ZONE, "example.com.").unwrap();
            zones.insert(zone.origin().to_string(), zone);
            let metrics = DnsMetrics::new();

            let response = make_response(
                &query("www.example.com.", record_types::A, true),
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
            generate_keys("example.com", &dir.0, "ECDSAP256SHA256").expect("generate");

            let zone_path = dir.0.join("example.com.zone");
            std::fs::write(&zone_path, SIGNED_ZONE).unwrap();

            let cli = Cli::parse_from([
                "rdnsd",
                "--zone-dir",
                dir.0.to_str().unwrap(),
                "--signing-key-dir",
                dir.0.to_str().unwrap(),
            ]);
            let signing = ZoneSigning::load(&cli).expect("load keys").expect("configured");

            let mut zones =
                enumerate_zone_files(dir.0.to_str().unwrap(), false).expect("zones");
            signing.apply(&mut zones).expect("sign");

            // Checked with the same validator the server runs before serving.
            let mut validator = DnssecValidator::new(true);
            validator.set_require_signed(true);
            verify_zones(&zones, &validator).expect("the zone we just signed verifies");

            let metrics = DnsMetrics::new();
            let response = make_response(
                &query("www.example.com.", record_types::A, true),
                &zones,
                &metrics,
            );
            assert_eq!(rrsigs_in(&response.answers).len(), 1);
        }

        #[test]
        fn require_signed_refuses_an_unsigned_zone_rather_than_serving_it() {
            let zone = parse_zone_file(SIGNED_ZONE, "example.com.").unwrap();
            let mut zones = HashMap::new();
            zones.insert(zone.origin().to_string(), zone);

            let mut validator = DnssecValidator::new(true);
            validator.set_require_signed(true);
            let err = verify_zones(&zones, &validator).unwrap_err();
            assert!(err.contains("not signed"), "{err}");

            // And without the assertion, the same zone is fine: most zones are
            // unsigned and serving them is the normal case.
            let permissive = DnssecValidator::new(true);
            assert!(verify_zones(&zones, &permissive).is_ok());
        }

        #[test]
        fn a_signature_that_stopped_matching_its_records_stops_the_server() {
            // The failure this check exists for: the zone file was edited and
            // the signatures were not renewed, so what goes out is signed data
            // that no longer says what the signature says it says.
            let (mut zones, _keys) = signed_server(false);
            let zone = zones.get_mut("example.com.").unwrap();
            let mut edited = Zone::new(zone.origin().to_string());
            for record in zone.records() {
                let mut record = record.clone();
                if record.name == "www.example.com." && record.rdata.rtype == record_types::A {
                    record.rdata =
                        RecordData::from_parsed(&rdns::ParsedRecord::A("198.51.100.9".parse().unwrap()))
                            .unwrap();
                }
                edited.add_record(record);
            }
            *zone = edited;

            let validator = DnssecValidator::new(true);
            let err = verify_zones(&zones, &validator).unwrap_err();
            assert!(err.contains("does not verify"), "{err}");
        }
    }
}
