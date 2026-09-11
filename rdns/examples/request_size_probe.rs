//! What a legitimate request weighs, against the 512-octet UDP admission cap.
//!
//! `TODO.md` #40f. `AdmissionLimits::max_udp_size` is RFC 1035 §4.2.1's 512 and
//! a request over it is dropped in silence — no FORMERR, nothing on the wire.
//! §14's rule is that a limit with no flag is a limit nobody has reviewed, and
//! its warning is to measure before adding a knob. This is that measurement: the
//! requests an operator actually sends, weighed on the wire.
//!
//! ```sh
//! cargo run --release -p rdns --example request_size_probe        # the cap today
//! cargo run --release -p rdns --example request_size_probe -- 512  # the old one
//! ```
//!
//! Not a benchmark — the numbers are byte counts and are the same on every
//! machine. Run it after changing anything that sizes a request.
//!
//! 2026-09-11, against the 512-octet cap this measurement retired:
//!
//! ```text
//!     request                                      plain   +TSIG
//!     one A record, one prerequisite                  74     171   fits
//!     A + AAAA for one host                           86     183   fits
//!     two ACME dns-01 TXT challenges                 177     266   fits
//!     a mail host moving: A, AAAA, MX, DMARC TXT     166     254   fits
//!     a 2048-bit DKIM key                            470     566   OVER
//!     ten ACME dns-01 TXT challenges                 809     898   OVER
//!     NOTIFY carrying the zone's SOA                  80     178   fits
//!     TSIG hmac-sha256 adds 86 octets (short key name), 115 (long)
//!     TSIG hmac-sha512 adds 118 octets (short key name), 147 (long)
//! ```
//!
//! The two that did not fit are the point, and so is *where* they stop fitting:
//! the DKIM rotation is 470 octets unsigned and 566 signed, so the TSIG the
//! server requires is what made a legitimate request inadmissible. The cap is
//! 4,096 now — what both daemons advertise they can reassemble — so every row
//! here fits, and the column is kept as the reason it moved.

use rdns::tsig::{sign_request, TsigAlgorithm, TsigKey};
use rdns::{
    notify, record_types, Class, DnsMessage, Name, OpCode, ParsedRecord, Qtype, QueryClass,
    QuerySection, RecordData, ResourceRecord, ResponseCode, Ttl,
};

/// The default UDP request cap, which is what `--max-udp-request` starts at and
/// what this measurement moved it to. Pass a cap as the one argument to weigh
/// these against another — `512` reproduces the table in the header.
const DEFAULT_UDP_CAP: usize = 4096;

fn name(text: &str) -> Name {
    Name::from_presentation(text).expect("a name")
}

fn rr(owner: &str, ttl: u32, parsed: ParsedRecord) -> ResourceRecord {
    ResourceRecord {
        name: name(owner),
        class: Class::new(1),
        ttl: Ttl::from_secs(ttl),
        rdata: RecordData::from_parsed(&parsed).expect("encodes"),
    }
}

/// An UPDATE (RFC 2136): the zone in the question section, the changes in the
/// authority section, prerequisites in the answer section.
fn update(
    zone: &str,
    prerequisites: Vec<ResourceRecord>,
    changes: Vec<ResourceRecord>,
) -> DnsMessage {
    DnsMessage {
        id: 0x2136,
        response: false,
        opcode: OpCode::Update,
        authoritive: false,
        truncation: false,
        recursion: false,
        recursion_ok: false,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![QuerySection {
            qname: name(zone),
            qtype: Qtype::of(record_types::SOA),
            qclass: QueryClass::IN,
        }],
        answers: prerequisites,
        authorities: changes,
        additionals: Vec::new(),
        edns: None,
    }
}

fn bytes(msg: &DnsMessage) -> Vec<u8> {
    msg.to_bytes_within(u16::MAX as usize).expect("serializes")
}

/// The same message signed, which is what any UPDATE an operator would accept
/// looks like: `rdnsd` refuses an unsigned one.
fn signed(msg: &DnsMessage, key_name: &str, alg: TsigAlgorithm) -> Vec<u8> {
    let key = TsigKey::new(key_name, alg, vec![0u8; 32]);
    sign_request(bytes(msg), &key, 1_757_500_000).expect("signs")
}

fn report(cap: usize, what: &str, plain: usize, with_tsig: usize) {
    let verdict = if with_tsig > cap {
        "OVER"
    } else if with_tsig > cap * 3 / 4 {
        "close"
    } else {
        "fits"
    };
    println!("{what:<44} {plain:>5} {with_tsig:>7}   {verdict}");
}

fn main() {
    let cap = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(DEFAULT_UDP_CAP);
    let report = |what: &str, plain: usize, with_tsig: usize| report(cap, what, plain, with_tsig);

    println!("{:<44} {:>5} {:>7}", "request", "plain", "+TSIG");
    println!("{}", "-".repeat(68));

    // A DHCP server registering one lease, which is the ordinary automated
    // UPDATE: the forward name, with the "does not exist" prerequisite
    // nsupdate's `prereq nxdomain` writes.
    let lease = update(
        "dyn.example.com.",
        vec![rr(
            "laptop-7.dyn.example.com.",
            0,
            ParsedRecord::A("0.0.0.0".parse().unwrap()),
        )],
        vec![rr(
            "laptop-7.dyn.example.com.",
            3600,
            ParsedRecord::A("192.0.2.17".parse().unwrap()),
        )],
    );
    report(
        "one A record, one prerequisite",
        bytes(&lease).len(),
        signed(
            &lease,
            "dhcp-updater.example.com.",
            TsigAlgorithm::HmacSha256,
        )
        .len(),
    );

    // The same, plus the reverse PTR — one message, because two are two chances
    // to half-apply.
    let lease_pair = update(
        "dyn.example.com.",
        Vec::new(),
        vec![
            rr(
                "laptop-7.dyn.example.com.",
                3600,
                ParsedRecord::A("192.0.2.17".parse().unwrap()),
            ),
            rr(
                "laptop-7.dyn.example.com.",
                3600,
                ParsedRecord::AAAA("2001:db8::17".parse().unwrap()),
            ),
        ],
    );
    report(
        "A + AAAA for one host",
        bytes(&lease_pair).len(),
        signed(
            &lease_pair,
            "dhcp-updater.example.com.",
            TsigAlgorithm::HmacSha256,
        )
        .len(),
    );

    // An ACME dns-01 challenge: a TXT of a 43-character base64url digest at
    // `_acme-challenge`, which is the most common UPDATE a small site ever
    // sends. Two of them, because a certificate with a SAN needs one per name
    // and they are answered together.
    let token = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
    let acme = update(
        "example.com.",
        Vec::new(),
        vec![
            rr(
                "_acme-challenge.example.com.",
                60,
                ParsedRecord::TXT(vec![token.as_bytes().to_vec()]),
            ),
            rr(
                "_acme-challenge.www.example.com.",
                60,
                ParsedRecord::TXT(vec![token.as_bytes().to_vec()]),
            ),
        ],
    );
    report(
        "two ACME dns-01 TXT challenges",
        bytes(&acme).len(),
        signed(&acme, "acme.example.com.", TsigAlgorithm::HmacSha256).len(),
    );

    // A mail host moving: the four records that name it, which is the smallest
    // realistic "change a service" update.
    let mail = update(
        "example.com.",
        Vec::new(),
        vec![
            rr(
                "mail.example.com.",
                3600,
                ParsedRecord::A("192.0.2.25".parse().unwrap()),
            ),
            rr(
                "mail.example.com.",
                3600,
                ParsedRecord::AAAA("2001:db8::25".parse().unwrap()),
            ),
            rr(
                "example.com.",
                3600,
                ParsedRecord::MX {
                    preference: 10,
                    exchange: name("mail.example.com."),
                },
            ),
            rr(
                "_dmarc.example.com.",
                3600,
                ParsedRecord::TXT(vec![
                    b"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com".to_vec(),
                ]),
            ),
        ],
    );
    report(
        "a mail host moving: A, AAAA, MX, DMARC TXT",
        bytes(&mail).len(),
        signed(&mail, "ops.example.com.", TsigAlgorithm::HmacSha256).len(),
    );

    // A DKIM key (RFC 6376 §3.6.1): a 2048-bit RSA public key is ~392 octets of
    // base64, which a TXT record carries as three character-strings because one
    // is capped at 255 (RFC 1035 §3.3.14). Rotating a DKIM selector is an
    // ordinary automated UPDATE, and this is the first one that does not fit.
    let dkim_key: String = std::iter::repeat_n('A', 392).collect();
    let dkim_txt: Vec<Vec<u8>> = {
        let value = format!("v=DKIM1; k=rsa; p={dkim_key}");
        value.as_bytes().chunks(255).map(<[u8]>::to_vec).collect()
    };
    let dkim = update(
        "example.com.",
        Vec::new(),
        vec![rr(
            "s2026._domainkey.example.com.",
            3600,
            ParsedRecord::TXT(dkim_txt),
        )],
    );
    report(
        "a 2048-bit DKIM key",
        bytes(&dkim).len(),
        signed(&dkim, "dkim-rotate.example.com.", TsigAlgorithm::HmacSha256).len(),
    );

    // One ACME order for a certificate with ten SANs: one TXT per name, answered
    // together, so one UPDATE.
    let many_acme = update(
        "example.com.",
        Vec::new(),
        (0..10)
            .map(|i| {
                rr(
                    &format!("_acme-challenge.host{i}.example.com."),
                    60,
                    ParsedRecord::TXT(vec![token.as_bytes().to_vec()]),
                )
            })
            .collect(),
    );
    report(
        "ten ACME dns-01 TXT challenges",
        bytes(&many_acme).len(),
        signed(&many_acme, "acme.example.com.", TsigAlgorithm::HmacSha256).len(),
    );

    // A NOTIFY, which carries the zone's SOA (RFC 1996 §3.7) and is signed when
    // the secondary is TSIG'd.
    let soa = rr(
        "example.com.",
        3600,
        ParsedRecord::SOA {
            mname: name("ns1.example.com."),
            rname: name("hostmaster.example.com."),
            serial: rdns::Serial::new(2026091101),
            refresh: 3600,
            retry: 600,
            expire: 604800,
            minimum: 300,
        },
    );
    let notify = notify::notify_request(name("example.com.").as_ref(), Some(soa), 1);
    report(
        "NOTIFY carrying the zone's SOA",
        bytes(&notify).len(),
        signed(
            &notify,
            "secondary-key.example.com.",
            TsigAlgorithm::HmacSha256,
        )
        .len(),
    );

    // What the signature itself costs, since it is the fixed part of every
    // number above and the one an operator cannot shrink.
    let bare = update("example.com.", Vec::new(), Vec::new());
    let bare_len = bytes(&bare).len();
    for (alg, label) in [
        (TsigAlgorithm::HmacSha256, "hmac-sha256"),
        (TsigAlgorithm::HmacSha512, "hmac-sha512"),
    ] {
        let short = signed(&bare, "k.example.com.", alg).len() - bare_len;
        let long =
            signed(&bare, "a-rather-long-key-name.updates.example.com.", alg).len() - bare_len;
        println!("TSIG {label:<12} adds {short:>4} octets (short key name), {long} (long)");
    }

    println!();
    println!("the cap is {cap} octets, and a request over it is dropped in silence");
}
