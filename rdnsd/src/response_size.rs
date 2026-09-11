//! What a signed answer off this server weighs, against the ceilings a UDP
//! response could be given.
//!
//! `TODO.md` #41b, and the response-side sibling of
//! `rdns/examples/request_size_probe.rs`. Before #41 a UDP reply's only ceiling
//! was the client's own EDNS advertisement, so a client asking for 65,535 got
//! whatever the answer weighed and the IP layer fragmented it. Choosing a
//! ceiling of our own means knowing what this server's answers actually weigh,
//! which is what this measures — through `write_response`, not through a second
//! serializer that would agree with nothing (`CLAUDE.md` §1).
//!
//! ```sh
//! cargo test -p rdnsd response_size -- --nocapture
//! ```
//!
//! Octets, so the numbers read the same on every machine. A `#[test]` rather
//! than an example because the answer path is `pub(crate)` here: `rdnsd` has no
//! library target, and a probe that reimplemented the four cases of RFC 1034
//! §4.3.2 would be measuring itself.
//!
//! 2026-09-11, against the zone below:
//!
//! ```text
//!     question                             DO=0  nsec/p256  nsec3/p256  nsec3/p384
//!     A www.example.com.                     60        167         167         199
//!     SOA example.com.                       91        198         198         230
//!     TXT s2026._domainkey (DKIM 2048)      545        652         652         684
//!     DNSKEY example.com.                    91        307         307         403
//!     A pool.example.com. (16 A)            301        408         408         440
//!     AAAA pool.example.com. (16 AAAA)      493        600         600         632
//!     ANY pool.example.com.                 749        963         963        1027
//!     ANY example.com.                      256       1165        1289        1609
//!     A nx.example.com. (NXDOMAIN)           94        499         760         888
//!     MX www.example.com. (NODATA)           95        342         388         452
//!     A a.wild.example.com. (wildcard)       63        316         348         412
//!     A x.secure (signed referral)           82        237         237         269
//!
//!     over 512: 5 of 18   over 1232: 1 of 18   over 4096: 0 of 18
//!
//!     during a ZSK rollover (nsec3/p256)        steady    rolling
//!     ANY example.com.                            1289       2118
//!     A nx.example.com. (NXDOMAIN)                 760       1188
//!     ANY pool.example.com.                        963       1177
//! ```
//!
//! What the default is chosen from: at 1232 exactly one question in this zone
//! truncates, and it is ANY at a signed apex — which RFC 8482 exists to make
//! small and which no resolver asks in the course of resolving. Everything a
//! resolver actually asks fits, with the NXDOMAIN proof the nearest at 760, and
//! 1188 of the 1232 while a ZSK rollover doubles every signature. That last row
//! is the one that says the margin is thin rather than generous: a longer zone
//! name, P-384, or an RSA key puts it over, and over means one TCP retry rather
//! than a wrong answer.
//!
//! Not measured: RSA, whose signatures are four times P-256's. `ring` signs
//! with an imported RSA key but cannot generate one
//! (`dnssec_key::SigningKey::generate`), so a number for it would have to come
//! from a private key checked into the tree. The two ECDSA curves bracket what
//! this tree can produce, and the P-384 column is what stands in for "a larger
//! signature".

use rdns::clock::current_unix_timestamp;
use rdns::dnssec::{DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE};
use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::metrics::DnsMetrics;
use rdns::record_types as rt;
use rdns::zone::parse_zone_file;
use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
use rdns::{DnsMessage, DnsMessageBuilder, Qtype, UdpSizes};

use crate::answer::write_response;
use crate::testutil::nm;
use crate::zones::Zones;
use crate::Scratch;

/// A small-business zone, which is the shape this server is for: a mail host,
/// the three TXT records every domain now carries, one signed delegation and
/// one insecure one, and a wildcard under a subdomain so that a genuine
/// NXDOMAIN is still askable.
const ZONE: &str = r#"$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1.example.com. hostmaster.example.com. ( 2026091101 3600 600 604800 300 )
@       IN NS  ns1.example.com.
@       IN NS  ns2.example.com.
@       IN MX  10 mail.example.com.
@       IN MX  20 mail2.example.com.
@       IN A   192.0.2.1
@       IN AAAA 2001:db8::1
@       IN TXT "v=spf1 mx a:mail.example.com -all"
ns1     IN A   192.0.2.2
ns1     IN AAAA 2001:db8::2
ns2     IN A   192.0.2.3
ns2     IN AAAA 2001:db8::3
www     IN A   192.0.2.10
www     IN AAAA 2001:db8::10
mail    IN A   192.0.2.25
mail    IN AAAA 2001:db8::25
mail2   IN A   192.0.2.26
_dmarc  IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
s2026._domainkey IN TXT ( "v=DKIM1; k=rsa; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" )
pool    IN A   192.0.2.100
pool    IN A   192.0.2.101
pool    IN A   192.0.2.102
pool    IN A   192.0.2.103
pool    IN A   192.0.2.104
pool    IN A   192.0.2.105
pool    IN A   192.0.2.106
pool    IN A   192.0.2.107
pool    IN A   192.0.2.108
pool    IN A   192.0.2.109
pool    IN A   192.0.2.110
pool    IN A   192.0.2.111
pool    IN A   192.0.2.112
pool    IN A   192.0.2.113
pool    IN A   192.0.2.114
pool    IN A   192.0.2.115
pool    IN AAAA 2001:db8::64
pool    IN AAAA 2001:db8::65
pool    IN AAAA 2001:db8::66
pool    IN AAAA 2001:db8::67
pool    IN AAAA 2001:db8::68
pool    IN AAAA 2001:db8::69
pool    IN AAAA 2001:db8::6a
pool    IN AAAA 2001:db8::6b
pool    IN AAAA 2001:db8::6c
pool    IN AAAA 2001:db8::6d
pool    IN AAAA 2001:db8::6e
pool    IN AAAA 2001:db8::6f
pool    IN AAAA 2001:db8::70
pool    IN AAAA 2001:db8::71
pool    IN AAAA 2001:db8::72
pool    IN AAAA 2001:db8::73
*.wild  IN A   192.0.2.99
secure  IN NS  ns.secure.example.com.
secure  IN DS  12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns.secure IN A 192.0.2.20
plain   IN NS  ns.plain.example.com.
ns.plain IN A  192.0.2.30
"#;

/// The zone signed one way, ready to answer. `zsks` is 1 in the steady state
/// and 2 mid-rollover, which is what the apex key set and every RRSIG double
/// for (RFC 6781 §4.1.1).
fn signed(algorithm: SigningAlgorithm, chain: DenialChain, zsks: usize) -> Zones {
    let mut keys = vec![SigningKey::generate(
        algorithm,
        "example.com.",
        DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
    )
    .expect("a KSK")];
    for _ in 0..zsks {
        keys.push(
            SigningKey::generate(algorithm, "example.com.", DNSKEY_FLAG_ZONE).expect("a ZSK"),
        );
    }
    let policy = SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400).with_chain(chain);
    let zone = sign_zone(
        &parse_zone_file(ZONE, "example.com.").expect("the zone parses"),
        &keys,
        &policy,
    )
    .expect("the zone signs");
    let mut zones = Zones::default();
    drop(zones.insert(zone));
    zones
}

/// A query advertising the largest payload EDNS can express, so the answer is
/// weighed rather than truncated.
fn ask(qname: &str, qtype: Qtype, dnssec_ok: bool) -> DnsMessage {
    DnsMessageBuilder::new()
        .with_id(0x4100)
        .with_query(nm(qname), qtype)
        .with_recursion(false)
        .with_edns(u16::MAX, dnssec_ok)
        .build()
}

/// What the datagram for this question weighs, with nothing capping it.
fn weigh(zones: &Zones, msg: &DnsMessage) -> usize {
    let mut scratch = Scratch::default();
    write_response(
        msg,
        zones,
        &DnsMetrics::new(),
        u16::MAX as usize,
        UdpSizes::default().advertised(),
        &mut scratch,
    )
    .expect("the response serializes");
    assert!(
        !DnsMessage::try_from_bytes(&scratch.out)
            .expect("and parses back")
            .truncation,
        "nothing may truncate at the ceiling this measurement removes"
    );
    scratch.out.len()
}

/// The question shapes a ceiling has to be chosen against: ordinary positive
/// answers, the three that carry a denial, the two referrals, and the apex
/// records that are the largest a zone has.
const QUESTIONS: &[(&str, &str, Qtype)] = &[
    ("A www.example.com.", "www.example.com.", Qtype::of(rt::A)),
    (
        "AAAA www.example.com.",
        "www.example.com.",
        Qtype::of(rt::AAAA),
    ),
    ("SOA example.com.", "example.com.", Qtype::of(rt::SOA)),
    ("NS example.com.", "example.com.", Qtype::of(rt::NS)),
    ("MX example.com.", "example.com.", Qtype::of(rt::MX)),
    ("TXT example.com. (SPF)", "example.com.", Qtype::of(rt::TXT)),
    (
        "TXT _dmarc.example.com.",
        "_dmarc.example.com.",
        Qtype::of(rt::TXT),
    ),
    (
        "TXT s2026._domainkey (DKIM 2048)",
        "s2026._domainkey.example.com.",
        Qtype::of(rt::TXT),
    ),
    ("DNSKEY example.com.", "example.com.", Qtype::of(rt::DNSKEY)),
    (
        "A pool.example.com. (16 A)",
        "pool.example.com.",
        Qtype::of(rt::A),
    ),
    (
        "AAAA pool.example.com. (16 AAAA)",
        "pool.example.com.",
        Qtype::of(rt::AAAA),
    ),
    ("ANY pool.example.com.", "pool.example.com.", Qtype::ANY),
    ("ANY example.com.", "example.com.", Qtype::ANY),
    (
        "A nx.example.com. (NXDOMAIN)",
        "nx.example.com.",
        Qtype::of(rt::A),
    ),
    (
        "MX www.example.com. (NODATA)",
        "www.example.com.",
        Qtype::of(rt::MX),
    ),
    (
        "A a.wild.example.com. (wildcard)",
        "a.wild.example.com.",
        Qtype::of(rt::A),
    ),
    (
        "A x.secure.example.com. (signed referral)",
        "x.secure.example.com.",
        Qtype::of(rt::A),
    ),
    (
        "A x.plain.example.com. (insecure referral)",
        "x.plain.example.com.",
        Qtype::of(rt::A),
    ),
];

#[test]
fn what_a_signed_answer_weighs() {
    let columns: [(&str, SigningAlgorithm, DenialChain); 3] = [
        (
            "nsec/p256",
            SigningAlgorithm::EcdsaP256Sha256,
            DenialChain::Nsec,
        ),
        (
            "nsec3/p256",
            SigningAlgorithm::EcdsaP256Sha256,
            DenialChain::nsec3(),
        ),
        (
            "nsec3/p384",
            SigningAlgorithm::EcdsaP384Sha384,
            DenialChain::nsec3(),
        ),
    ];

    let signed_zones: Vec<(&str, Zones)> = columns
        .iter()
        .map(|(label, alg, chain)| (*label, signed(*alg, chain.clone(), 1)))
        .collect();
    // The DO=0 column is an *unsigned* zone: DNSSEC records are not answer data
    // unless DO asked for them (RFC 4035 §3.1.1), so this is what the same
    // question costs a deployment that does not sign at all.
    let plain = {
        let mut zones = Zones::default();
        drop(zones.insert(parse_zone_file(ZONE, "example.com.").expect("the zone parses")));
        zones
    };

    let measure = |zones: &Zones, qname: &str, qtype: Qtype, dnssec_ok: bool| {
        weigh(zones, &ask(qname, qtype, dnssec_ok))
    };

    println!();
    print!("{:<42} {:>6}", "question", "DO=0");
    for (label, _, _) in &columns {
        print!(" {label:>11}");
    }
    println!();
    println!("{}", "-".repeat(82));

    let mut worst = 0usize;
    for (what, qname, qtype) in QUESTIONS {
        print!("{:<42} {:>6}", what, measure(&plain, qname, *qtype, false));
        for (_, zones) in &signed_zones {
            let len = measure(zones, qname, *qtype, true);
            worst = worst.max(len);
            print!(" {len:>11}");
        }
        println!();
    }

    println!();
    for ceiling in [512usize, 1232, 4096] {
        let over: Vec<&str> = QUESTIONS
            .iter()
            .filter(|(_, qname, qtype)| {
                signed_zones
                    .iter()
                    .any(|(_, zones)| measure(zones, qname, *qtype, true) > ceiling)
            })
            .map(|(what, _, _)| *what)
            .collect();
        println!(
            "over {ceiling}: {} of {}  {over:?}",
            over.len(),
            QUESTIONS.len()
        );
    }
    println!("the largest signed answer here is {worst} octets");

    // A ZSK rollover publishes two zone keys and signs every RRset with both
    // (RFC 6781 §4.1.1), so the whole table moves for as long as it runs. The
    // three rows it moves most are the ones already nearest a ceiling.
    println!();
    println!(
        "{:<42} {:>11} {:>11}",
        "during a ZSK rollover", "steady", "rolling"
    );
    let rolling = signed(SigningAlgorithm::EcdsaP256Sha256, DenialChain::nsec3(), 2);
    let steady = &signed_zones[1].1;
    for (what, qname, qtype) in QUESTIONS {
        let (before, after) = (
            measure(steady, qname, *qtype, true),
            measure(&rolling, qname, *qtype, true),
        );
        if after > 512 {
            println!("{what:<42} {before:>11} {after:>11}");
        }
        worst = worst.max(after);
    }

    // The one assertion, and it is about the *other* default an operator might
    // reach for: `--max-udp-response 4096` is "the old behaviour, bounded", and
    // it is only that if nothing this zone can answer exceeds it. A row that
    // grows past 4096 is a row that starts forcing TCP at a setting whose whole
    // point is not to — file what moved it rather than raising the number
    // (`CLAUDE.md` §10).
    assert!(
        worst <= 4096,
        "the largest answer here is {worst} octets, over the 4096 an operator \
         raising the cap would reach for"
    );
}
