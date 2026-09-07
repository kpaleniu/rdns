//! The pre-authentication path against mutated wire data: everything a
//! datagram touches before a TSIG MAC is verified, and for an unsigned query
//! everything up to serializing the answer.
//!
//! The UDP path answers inline, so a panic there ends the worker and `serve`
//! ends the process: any reachable panic is a remote kill switch. Hand-rolled
//! rather than `cargo-fuzz` (nightly-only) because random bytes never get past
//! the header check — what finds anything is mutating valid messages.
//!
//! A soak is the same test with more cases:
//!
//! ```sh
//! RDNS_FUZZ_ITERATIONS=2000000 cargo test -p rdns --test no_input_panics -- --nocapture
//! RDNS_FUZZ_SEED=12345 cargo test -p rdns --test no_input_panics
//! ```

use std::panic::{catch_unwind, AssertUnwindSafe};

use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::utils::{current_unix_timestamp, record_types};
use rdns::validation::AdmissionCheck;
use rdns::zone::{parse_zone_file, NameKind, Zone};
use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
use rdns::{
    dnssec_answer, tsig, DnsMessage, DnsMessageBuilder, Edns, EdnsOption, Qtype, ResourceRecord,
};

/// Cases per corpus entry. Small enough to stay under a second in CI.
const ITERATIONS: usize = 250;

/// A seeded xorshift64*, so a failing run is reproducible from its seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // Not cryptographic and does not need to be: it decides which byte to
        // corrupt, not what a key is.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn zone_text() -> String {
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

fn query_message(qname: &str, qtype: Qtype) -> DnsMessage {
    DnsMessageBuilder::new()
        .with_id(0x1234)
        .with_query(qname, qtype)
        .with_recursion(false)
        .build()
}

/// Valid messages to mutate, covering the shapes whose parsers have length
/// fields, pointers or nesting in them.
///
/// Built through the library so the pointers, RDLENGTHs and option lengths are
/// correct: a mutation then lands on a real field rather than on a byte the
/// parser was going to reject anyway.
fn corpus(zone: &Zone, signed: &Zone) -> Vec<(&'static str, Vec<u8>)> {
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
        // Every RDATA with a length field an attacker picks. DNAME's is the
        // name; SVCB and HTTPS carry a 16-bit length *per parameter*, read in
        // a loop, which is the shape `CLAUDE.md` §2 opens with.
        ("redir.example.com.", record_types::DNAME),
        ("svc.example.com.", record_types::HTTPS),
        ("svc.example.com.", record_types::SVCB),
    ] {
        for record in zone.query(name, Qtype::of(qtype)) {
            answer.answers.push(ResourceRecord {
                name: name.to_string(),
                class: record.class,
                ttl: record.ttl,
                rdata: record.rdata.clone(),
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
        for record in signed.query(name, Qtype::of(qtype)) {
            secure.answers.push(ResourceRecord {
                name: name.to_string(),
                class: record.class,
                ttl: record.ttl,
                rdata: record.rdata.clone(),
            });
        }
    }
    out.push((
        "a signed response",
        secure.to_bytes_within(65_535).expect("serialize"),
    ));

    // The one query that carries a record of its own, in the authority section.
    let mut ixfr = query_message("example.com.", Qtype::of(record_types::IXFR));
    for soa in zone.query("example.com.", Qtype::of(record_types::SOA)) {
        ixfr.authorities.push(ResourceRecord {
            name: "example.com.".to_string(),
            class: soa.class,
            ttl: soa.ttl,
            rdata: soa.rdata.clone(),
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

/// One mutation of `seed_bytes`, chosen by `rng`.
///
/// Truncation finds parsers that read past what arrived; the bias towards `0xc0`
/// and `0xff` aims at the two structurally meaningful values on the wire, a
/// compression pointer and a maximal length field.
fn mutate(rng: &mut Rng, seed_bytes: &[u8]) -> Vec<u8> {
    let mut data = seed_bytes.to_vec();
    if data.is_empty() {
        return data;
    }
    match rng.below(6) {
        // Flip one to four bits.
        0 => {
            for _ in 0..=rng.below(4) {
                let at = rng.below(data.len());
                data[at] ^= 1 << rng.below(8);
            }
        }
        // Cut it short, anywhere.
        1 => {
            let at = rng.below(data.len());
            data.truncate(at);
        }
        // Write a structurally interesting byte.
        2 => {
            let at = rng.below(data.len());
            data[at] = match rng.below(4) {
                0 => 0xc0,
                1 => 0xff,
                2 => 0x00,
                _ => (rng.next() & 0xff) as u8,
            };
        }
        // Write a whole 16-bit field: a length, a count, a pointer.
        3 => {
            if data.len() >= 2 {
                let at = rng.below(data.len() - 1);
                let value: u16 = match rng.below(4) {
                    0 => 0xffff,
                    1 => 0xc000,
                    2 => 0x0000,
                    _ => (rng.next() & 0xffff) as u16,
                };
                data[at..at + 2].copy_from_slice(&value.to_be_bytes());
            }
        }
        // Splice a run of random bytes over the middle.
        4 => {
            let at = rng.below(data.len());
            let run = 1 + rng.below(8);
            for i in 0..run {
                if at + i < data.len() {
                    data[at + i] = (rng.next() & 0xff) as u8;
                }
            }
        }
        // Arbitrary, occasionally longer than any datagram this server accepts.
        _ => {
            let len = rng.below(600);
            data = (0..len).map(|_| (rng.next() & 0xff) as u8).collect();
        }
    }
    data
}

/// Everything a stranger's bytes reach before anything has authenticated them,
/// ordered as the daemons order it.
///
/// Serializing back out belongs here as much as parsing: a response echoes the
/// client's question, so an attacker-shaped name goes through the writer too.
fn exercise(data: &[u8], zone: &Zone, signed: &Zone, keyring: &tsig::TsigKeyring, now: u64) {
    let validator = AdmissionCheck::with_defaults();
    let _ = validator.validate_packet(data, false);
    let _ = validator.validate_packet(data, true);
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
            let _ = z.query(&query.qname, query.qtype);
            let kind = z.name_kind(&query.qname);
            let _ = z.name_exists(&query.qname);
            let _ = z.holds_name(&query.qname);
            let _ = z.delegation_for(&query.qname);
            let _ = z.normalize_name(&query.qname);
            let _ = z.matches_query("www.example.com.", &query.qname);

            // The DO-bit path: signatures, and the three denials. Each into
            // its own reply, because the writer takes sections in order.
            let mut out = Vec::new();
            let mut compressor = rdns::compression::NameCompressor::new();
            let mut into = |f: &mut dyn FnMut(&mut rdns::response::ResponseWriter)| {
                let Ok(mut w) = rdns::response::ResponseWriter::start(
                    &mut out,
                    &mut compressor,
                    u16::MAX as usize,
                    &msg,
                ) else {
                    return;
                };
                f(&mut w);
                let _ = w.finish();
            };
            into(&mut |w| {
                let canonical = rdns::dnssec::canonical_name(&query.qname);
                let _ = dnssec_answer::push_answer_signatures(
                    &z.locate(&canonical),
                    &canonical,
                    query.qtype,
                    w,
                );
            });
            into(&mut |w| {
                let _ = dnssec_answer::push_negative_proof(z, &query.qname, &kind, w);
            });
            into(&mut |w| {
                let _ = dnssec_answer::push_negative_proof(z, &query.qname, &NameKind::NotFound, w);
            });
            into(&mut |w| {
                let _ = dnssec_answer::push_proof_of_absence(z, &query.qname, w);
            });
            into(&mut |w| {
                let _ = dnssec_answer::push_delegation_proof(z, &query.qname, w);
            });
        }
    }

    // Back onto the wire, at both the UDP and the TCP ceiling.
    let mut scratch = Vec::new();
    let _ = msg.to_bytes_within_buf(512, &mut scratch);
    let _ = msg.to_bytes_within_buf(65_535, &mut scratch);
}

#[test]
fn no_input_panics_before_authentication() {
    let seed: u64 = std::env::var("RDNS_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5eed_1234_abcd_0001);
    let iterations: usize = std::env::var("RDNS_FUZZ_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(ITERATIONS);

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

    let key =
        tsig::TsigKey::parse("hmac-sha256:probe.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
            .expect("the key spec parses");
    let keyring = tsig::TsigKeyring::new(vec![key]);
    let now = current_unix_timestamp();

    let corpus = corpus(&zone, &signed);
    let mut rng = Rng(seed);
    let mut cases = 0u64;

    println!(
        "seed {seed:#x}, {iterations} iterations over {} corpus entries",
        corpus.len()
    );

    for (what, seed_bytes) in &corpus {
        // Unmutated first: if the corpus itself panics, the rest is noise.
        check(seed_bytes, what, seed, cases, &zone, &signed, &keyring, now);
        cases += 1;

        for _ in 0..iterations {
            let data = mutate(&mut rng, seed_bytes);
            check(&data, what, seed, cases, &zone, &signed, &keyring, now);
            cases += 1;
        }
    }

    println!("{cases} cases, no panics");
}

/// Run one case, and turn a panic into a message that says how to reproduce it:
/// the seed, and the bytes to paste into the regression test.
#[allow(clippy::too_many_arguments)]
fn check(
    data: &[u8],
    what: &str,
    seed: u64,
    case: u64,
    zone: &Zone,
    signed: &Zone,
    keyring: &tsig::TsigKeyring,
    now: u64,
) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        exercise(data, zone, signed, keyring, now)
    }));
    if outcome.is_err() {
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        panic!(
            "panicked on case {case} (seed {seed:#x}), a mutation of {what}:\n\
             {hex}\n\
             reproduce with RDNS_FUZZ_SEED={seed}"
        );
    }
}
