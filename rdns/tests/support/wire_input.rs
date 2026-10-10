//! The wire inputs the panic harnesses share: `tests/no_input_panics.rs` on
//! stable and the `fuzz/` targets, which include this file by path so both
//! drive the same code with the same seeds (`TODO.md` #204).

// Each includer uses part of this.
#![allow(dead_code)]

use rdns::clock::current_unix_timestamp;
use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::ixfr::DeltaLog;
use rdns::record_types;
use rdns::validation::{AdmissionCheck, Transport};
use rdns::zone::{parse_zone_file, Zone};
use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
use rdns::{
    tsig, DnsMessage, DnsMessageBuilder, Edns, EdnsOption, Name, Qtype, ResourceRecord, Rtype,
};

/// A name from a literal, for tests only: `Name` is fallible to build and a test
/// that writes a bad one should fail loudly at that line.
pub fn nm(text: &str) -> Name {
    text.parse().expect("a test name parses")
}

/// The zones and key every wire-input harness runs against: the test zone,
/// the same zone signed with NSEC3, and a TSIG keyring holding the corpus's key.
pub struct Fixture {
    pub zone: Zone,
    pub signed: Zone,
    pub keyring: tsig::TsigKeyring,
    pub now: u64,
}

impl Fixture {
    pub fn new() -> Fixture {
        let zone = parse_zone_file(&zone_text(), "example.com.").expect("the test zone parses");
        let keys = vec![
            SigningKey::generate(
                SigningAlgorithm::EcdsaP256Sha256,
                "example.com.",
                rdns::dnssec::DNSKEY_FLAG_ZONE | rdns::dnssec::DNSKEY_FLAG_SEP,
            )
            .expect("ksk"),
            SigningKey::generate(
                SigningAlgorithm::EcdsaP256Sha256,
                "example.com.",
                rdns::dnssec::DNSKEY_FLAG_ZONE,
            )
            .expect("zsk"),
        ];
        // NSEC3 rather than NSEC: a hash, a salt, an iteration count and a base32
        // label is more arithmetic on wire-derived values.
        let policy = SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400).with_chain(
            DenialChain::Nsec3 {
                salt: vec![0xab, 0xcd],
                iterations: 10,
                opt_out: false,
            },
        );
        let signed = sign_zone(&zone, &keys, &policy).expect("the test zone signs");

        let key = tsig::TsigKey::parse(
            "hmac-sha256:probe.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
        )
        .expect("the key spec parses");
        let keyring = tsig::TsigKeyring::new(vec![key]);
        let now = current_unix_timestamp();
        Fixture {
            zone,
            signed,
            keyring,
            now,
        }
    }
}

pub fn zone_text() -> String {
    "$ORIGIN example.com.\n\
     $TTL 3600\n\
     @      IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
     @      IN NS  ns1.example.com.\n\
     ns1    IN A   192.0.2.1\n\
     www    IN A   192.0.2.10\n\
     www    IN AAAA 2001:db8::10\n\
     mail   IN MX  10 mx.example.com.\n\
     mx     IN A   192.0.2.20\n\
     txt    IN TXT \"some text\"\n\
     alias  IN CNAME www.example.com.\n\
     sub    IN NS  ns.sub.example.com.\n\
     ns.sub IN A   192.0.2.30\n\
     redir  IN DNAME target.example.net.\n\
     svc    IN HTTPS 1 . alpn=\"h2,h3\" port=8002 ipv4hint=192.0.2.1\n\
     svc    IN SVCB  16 foo.example.org. mandatory=alpn key667=\"x\\\\210y\"\n\
     *      IN A   192.0.2.99\n"
        .to_string()
}

pub fn query_message(qname: &str, qtype: Qtype) -> DnsMessage {
    DnsMessageBuilder::new()
        .with_id(0x1234)
        .with_query(nm(qname), qtype)
        .with_recursion(false)
        .build()
}

/// Valid messages to mutate, covering the shapes whose parsers have length
/// fields, pointers or nesting in them.
///
/// Built through the library so the pointers, RDLENGTHs and option lengths are
/// correct: a mutation then lands on a real field rather than on a byte the
/// parser was going to reject anyway.
pub fn corpus(zone: &Zone, signed: &Zone) -> Vec<(&'static str, Vec<u8>)> {
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();

    let plain = query_message("www.example.com.", Qtype::of(record_types::A));
    out.push((
        "a plain query",
        plain.to_bytes_within(512).expect("serialize"),
    ));

    let mut edns = query_message("www.example.com.", Qtype::of(record_types::A));
    edns.set_edns(
        Edns::with_options(
            1232,
            0,
            true,
            &[
                EdnsOption {
                    code: rdns::EDNS_OPTION_COOKIE,
                    data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
                EdnsOption {
                    code: rdns::EDNS_OPTION_NSID,
                    data: Vec::new(),
                },
            ],
        )
        .expect("encode the options"),
    );
    out.push((
        "a query with EDNS and two options",
        edns.to_bytes_within(512).expect("serialize"),
    ));

    // Every record shape the zone has: the RDATA parsers and the compression
    // pointers.
    let mut answer = query_message("example.com.", Qtype::of(record_types::ANY));
    answer.response = true;
    answer.authoritive = true;
    for (name, qtype) in [
        ("www.example.com.", record_types::A),
        ("www.example.com.", record_types::AAAA),
        ("mail.example.com.", record_types::MX),
        ("txt.example.com.", record_types::TXT),
        ("alias.example.com.", record_types::CNAME),
        ("example.com.", record_types::SOA),
        ("example.com.", record_types::NS),
        // Every attacker-chosen RDATA length: DNAME's name, and SVCB and
        // HTTPS's 16-bit length per parameter (`CLAUDE.md` §2).
        ("redir.example.com.", record_types::DNAME),
        ("svc.example.com.", record_types::HTTPS),
        ("svc.example.com.", record_types::SVCB),
    ] {
        for record in zone.query(nm(name).as_ref(), Qtype::of(qtype)) {
            answer.answers.push(ResourceRecord {
                name: nm(name),
                class: record.class,
                ttl: record.ttl,
                rdata: record.rdata.to_owned(),
            });
        }
    }
    out.push((
        "a response with one of every record type",
        answer.to_bytes_within(4096).expect("serialize"),
    ));

    // RRSIG, DNSKEY and a denial chain: their own length fields and embedded
    // names.
    let mut secure = query_message("example.com.", Qtype::of(record_types::ANY));
    secure.response = true;
    secure.authoritive = true;
    for (name, qtype) in [
        ("example.com.", record_types::DNSKEY),
        ("example.com.", record_types::RRSIG),
        ("example.com.", record_types::NSEC),
        ("example.com.", record_types::NSEC3),
        ("example.com.", record_types::NSEC3PARAM),
    ] {
        for record in signed.query(nm(name).as_ref(), Qtype::of(qtype)) {
            secure.answers.push(ResourceRecord {
                name: nm(name),
                class: record.class,
                ttl: record.ttl,
                rdata: record.rdata.to_owned(),
            });
        }
    }
    out.push((
        "a signed response",
        secure.to_bytes_within(65_535).expect("serialize"),
    ));

    // The one query that carries a record of its own, in the authority section.
    let mut ixfr = query_message("example.com.", Qtype::of(record_types::IXFR));
    for soa in zone.query(nm("example.com.").as_ref(), Qtype::of(record_types::SOA)) {
        ixfr.authorities.push(ResourceRecord {
            name: nm(&nm("example.com.").to_string()),
            class: soa.class,
            ttl: soa.ttl,
            rdata: soa.rdata.to_owned(),
        });
    }
    out.push((
        "an IXFR request with the client's SOA",
        ixfr.to_bytes_within(512).expect("serialize"),
    ));

    // So `find_tsig`'s scan and the MAC check get mutated input too.
    let key =
        tsig::TsigKey::parse("hmac-sha256:probe.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
            .expect("the key spec parses");
    let unsigned = query_message("www.example.com.", Qtype::of(record_types::A))
        .to_bytes_within(512)
        .expect("serialize");
    if let Ok(signed_query) = tsig::sign_request(unsigned, &key, current_unix_timestamp()) {
        out.push(("a TSIG-signed query", signed_query));
    }

    out
}

/// Everything a stranger's bytes reach before anything has authenticated them,
/// ordered as the daemons order it.
///
/// Serializing back out belongs here as much as parsing: a response echoes the
/// client's question, so an attacker-shaped name goes through the writer too.
pub fn exercise(data: &[u8], zone: &Zone, signed: &Zone, keyring: &tsig::TsigKeyring, now: u64) {
    let validator = AdmissionCheck::with_defaults();
    let _ = validator.validate_packet(data, Transport::Udp);
    let _ = validator.validate_packet(data, Transport::Tcp);
    let _ = tsig::check_request(data, keyring, now);
    let _ = tsig::request_mac(data);

    let Ok(msg) = DnsMessage::try_from_bytes(data) else {
        return;
    };

    let _ = msg.edns();
    let _ = msg.edns_header();
    let _ = msg.has_edns();
    let _ = msg.udp_payload_size();

    // What `make_response` does with the question it was given.
    for query in &msg.queries {
        for z in [zone, signed] {
            let _ = z.query(query.qname.as_ref(), query.qtype);
            let _ = z.name_kind(query.qname.as_ref());
            let _ = z.name_exists(query.qname.as_ref());
            let _ = z.holds_name(query.qname.as_ref());
            let _ = z.delegation_for(query.qname.as_ref());
            let _ = z.matches_query(nm("www.example.com.").as_ref(), query.qname.as_ref());

            // The zone's answer with DO, as `rdnsd` writes it, not the proof
            // writers on names the answer path never sends them.
            let mut out = Vec::new();
            let mut compressor = rdns::compression::NameCompressor::new();
            if let Ok(mut w) = rdns::response::ResponseWriter::start(
                &mut out,
                &mut compressor,
                u16::MAX as usize,
                &msg,
            ) {
                let _ = rdns::zone_answer::write(z, &query.qname, query.qtype, true, &mut w);
                let _ = w.finish();
            }
        }
    }

    // Back onto the wire, at both the UDP and the TCP ceiling.
    let mut scratch = Vec::new();
    let _ = msg.to_bytes_within_buf(512, &mut scratch);
    let _ = msg.to_bytes_within_buf(65_535, &mut scratch);
}

/// Upstream replies to `www.example.com. A`, the query the resolver target
/// asks: an answer, a CNAME, a referral with glue, NXDOMAIN, and a signed
/// answer. The id is zero; the target copies the query's in.
pub fn upstream_replies(fx: &Fixture) -> Vec<(&'static str, Vec<u8>)> {
    let reply = |rcode, answers: &[(&str, Rtype, &Zone)], authorities: &[(&str, Rtype)]| {
        let mut m = query_message("www.example.com.", Qtype::of(record_types::A));
        m.id = 0;
        m.response = true;
        m.rcode = rcode;
        for (name, qtype, zone) in answers {
            m.answers.extend(owned(zone, name, *qtype));
        }
        for (name, qtype) in authorities {
            m.authorities.extend(owned(&fx.zone, name, *qtype));
        }
        m.to_bytes_within(65_535).expect("serialize")
    };
    use rdns::ResponseCode::{NoSuchDomain as NxDomain, Ok as NoError};
    vec![
        (
            "an answer",
            reply(
                NoError,
                &[("www.example.com.", record_types::A, &fx.zone)],
                &[],
            ),
        ),
        (
            "a CNAME and its target",
            reply(
                NoError,
                &[
                    ("alias.example.com.", record_types::CNAME, &fx.zone),
                    ("www.example.com.", record_types::A, &fx.zone),
                ],
                &[],
            ),
        ),
        ("a referral", {
            let mut m = DnsMessage::try_from_bytes(&reply(
                NoError,
                &[],
                &[("example.com.", record_types::NS)],
            ))
            .expect("parse");
            m.additionals
                .extend(owned(&fx.zone, "ns1.example.com.", record_types::A));
            m.to_bytes_within(65_535).expect("serialize")
        }),
        (
            "NXDOMAIN with the SOA",
            reply(NxDomain, &[], &[("example.com.", record_types::SOA)]),
        ),
        (
            "a signed answer",
            reply(
                NoError,
                &[
                    ("www.example.com.", record_types::A, &fx.signed),
                    ("www.example.com.", record_types::RRSIG, &fx.signed),
                ],
                &[],
            ),
        ),
    ]
}

/// Transfers of the fixture's zone as a secondary reads them off TCP, each
/// message behind its two-byte length: a whole zone (AXFR), and the step from
/// serial 1 to 2 (IXFR) against `fx.zone` as the version held.
pub fn transfers(fx: &Fixture) -> Vec<(&'static str, Vec<u8>)> {
    let framed = |messages: Vec<DnsMessage>| {
        let mut out = Vec::new();
        for m in messages {
            let wire = m.to_bytes_within(65_535).expect("serialize");
            out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
            out.extend_from_slice(&wire);
        }
        out
    };

    let axfr = query_message("example.com.", Qtype::of(record_types::AXFR));
    let whole = rdns::transfer::axfr_messages(&axfr, &fx.zone).expect("an AXFR");

    let v2 = parse_zone_file(
        &zone_text()
            .replace("( 1 3600", "( 2 3600")
            .replace("192.0.2.10", "192.0.2.11"),
        "example.com.",
    )
    .expect("version 2 parses");
    let mut log = DeltaLog::new();
    log.note_change(Some(&fx.zone), &v2);
    let mut ixfr = query_message("example.com.", Qtype::of(record_types::IXFR));
    ixfr.authorities
        .extend(owned(&fx.zone, "example.com.", record_types::SOA));
    let step = rdns::ixfr::ixfr_response(&ixfr, &v2, &log)
        .and_then(|r| r.messages(&ixfr, &v2))
        .expect("an IXFR");

    vec![("a whole zone", framed(whole)), ("one step", framed(step))]
}

fn owned(zone: &Zone, name: &str, qtype: Rtype) -> Vec<ResourceRecord> {
    zone.query(nm(name).as_ref(), Qtype::of(qtype))
        .into_iter()
        .map(|r| ResourceRecord {
            name: nm(name),
            class: r.class,
            ttl: r.ttl,
            rdata: r.rdata.to_owned(),
        })
        .collect()
}
