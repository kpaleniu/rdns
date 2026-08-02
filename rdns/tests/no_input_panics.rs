//! No input panics: the pre-authentication path against mutated wire data.
//!
//! **What this is for.** Everything a datagram touches before a TSIG MAC has
//! been verified — which for an unsigned query is *everything*, up to and
//! including the answer being serialized — runs on bytes a stranger chose. A
//! panic there used to cost one lost answer, because `rdnsd` spawned a task per
//! datagram and `tokio::spawn` swallows a task's panic. Since 2026-08-01 a fixed
//! pool of workers answers inline, so a panic ends the worker, `serve` treats a
//! stopped listener as fatal, and the **process exits**. That trade was taken
//! deliberately — a server that keeps accepting queries while every answer
//! panics is the quiet degradation this codebase keeps being bitten by — but it
//! converts any reachable panic into a remote kill switch. `TODO.md` #12 is the
//! audit that follows from it; this file is its empirical half.
//!
//! **Why a property test rather than a unit test.** The property needs no
//! oracle: there is no correct answer to check, only "this returned rather than
//! unwound". That is the cheapest useful test there is, and it would have caught
//! the RDLENGTH slice of #9b — `&rest[..rdatalen as usize]` with no bounds
//! check, a pre-authentication remote panic on both transports — inside the
//! first hundred inputs.
//!
//! **Why it is hand-rolled.** `cargo-fuzz` is nightly-only and this workspace
//! pins stable 1.95. `proptest` would do, but the generator here is not the
//! interesting part: random bytes essentially never get past the header check,
//! so what finds anything is *mutating valid messages* — flipping bits in a real
//! compression pointer, cutting a real RDLENGTH short. That corpus has to be
//! built out of this library either way, and once it is, the rest is a seeded
//! xorshift and a mutation switch. No dependency, and the seed makes every
//! failure reproducible.
//!
//! **Running it longer.** The suite runs `ITERATIONS` cases so it stays inside a
//! second. A real soak is the same test with more of them:
//!
//! ```sh
//! RDNS_FUZZ_ITERATIONS=2000000 cargo test -p rdns --test no_input_panics -- --nocapture
//! RDNS_FUZZ_SEED=12345 cargo test -p rdns --test no_input_panics
//! ```
//!
//! A failure prints the seed, the case number and the bytes as hex, which is
//! everything needed to write the regression test that goes with the fix.

use std::panic::{catch_unwind, AssertUnwindSafe};

use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::utils::{current_unix_timestamp, record_types};
use rdns::validation::RequestValidator;
use rdns::zone::{parse_zone_file, NameKind, Zone};
use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
use rdns::{
    dnssec_answer, tsig, DnsMessage, Edns, EdnsOption, OpCode, Qtype, QueryClass, QuerySection,
    ResourceRecord, ResponseCode,
};

/// Cases per corpus entry. Small enough to stay under a second in CI; the env
/// var is what a soak run turns up.
const ITERATIONS: usize = 250;

/// A seeded xorshift64*, so a failing run is reproducible from its seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*, Marsaglia. Not cryptographic and does not need to be: it
        // decides which byte to corrupt, not what a key is.
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
     *      IN A   192.0.2.99\n"
        .to_string()
}

fn query_message(qname: &str, qtype: Qtype) -> DnsMessage {
    DnsMessage {
        id: 0x1234,
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
        edns: None,
    }
}

/// Valid messages to mutate, covering the shapes whose parsers have length
/// fields, pointers or nesting in them.
///
/// Building them through the library rather than by hand is the point: the
/// compression pointers, RDLENGTHs and OPT option lengths are all *correct*
/// here, so a mutation lands on a real field rather than on a byte the parser
/// was going to reject anyway.
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

    // A response carrying every record shape the zone has, which is where the
    // RDATA parsers and the compression pointers are.
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

    // The DNSSEC shapes: RRSIG, DNSKEY and a denial chain, all with their own
    // length fields and embedded names.
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

    // An IXFR request, the one query that carries a record of its own — in the
    // authority section, which the validator used to reject outright.
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

    // A TSIG-signed query, so the scan in `find_tsig` and the MAC check get
    // mutated input too.
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
/// The mix is deliberate. Bit flips and byte writes find the parsers that
/// believe a length; truncation finds the ones that read past what arrived;
/// biasing written bytes towards `0xc0` and `0xff` aims at the two values that
/// mean something structural on the wire — a compression pointer and a maximal
/// length field.
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
        // Something completely arbitrary, occasionally longer than any datagram
        // this server would accept.
        _ => {
            let len = rng.below(600);
            data = (0..len).map(|_| (rng.next() & 0xff) as u8).collect();
        }
    }
    data
}

/// Everything a stranger's bytes reach before anything has authenticated them.
///
/// Ordered as the daemons order it: validate, parse, scan for a TSIG, then —
/// because `make_response` does all of this with the qname it was handed — the
/// zone lookups, the DNSSEC answer machinery, and serializing the result back
/// out. The last one matters as much as the first: a response echoes the
/// client's question, so an attacker-shaped name goes through the *writer* too.
fn exercise(data: &[u8], zone: &Zone, signed: &Zone, keyring: &tsig::TsigKeyring, now: u64) {
    let validator = RequestValidator::with_defaults();
    let _ = validator.validate_packet(data, false);
    let _ = validator.validate_packet(data, true);
    let _ = tsig::check_request(data, keyring, now);
    let _ = tsig::request_mac(data);

    let Ok(msg) = DnsMessage::try_from_bytes(data) else {
        return;
    };

    // The EDNS readers, both of them, and the size the reply is bounded by.
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

            // The DO-bit path: signatures for an answer, and the three denials.
            let _ = dnssec_answer::answer_signatures(z, &query.qname, query.qtype);
            let _ = dnssec_answer::negative_proof(z, &query.qname, &kind);
            let _ = dnssec_answer::negative_proof(z, &query.qname, &NameKind::NotFound);
            let _ = dnssec_answer::proof_of_absence(z, &query.qname);
            let _ = dnssec_answer::delegation_proof(z, &query.qname);
        }
    }

    // And back out onto the wire, at both the UDP and the TCP ceiling.
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
    // NSEC3 rather than NSEC: it has a hash, a salt, an iteration count and a
    // base32 label, which is more arithmetic on wire-derived values than the
    // NSEC chain has.
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
        // The unmutated message first: if the corpus itself panics, everything
        // after it is noise.
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

/// Run one case, and turn a panic into a message that says how to reproduce it.
///
/// The bytes are what the next reader needs: a panic with no input is a bug
/// report nobody can act on, and the whole value of a generated case is being
/// able to paste it into a `#[test]` as the regression that goes with the fix.
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
