//! Fixtures shared by this crate's two test modules.
//!
//! `lib.rs` had them and `tcp.rs` could not see them, which is `TODO.md` #38e
//! one module further in.

use std::sync::Arc;

use rdns::clock::Clock;
use rdns::logging::QueryLogger;
use rdns::metrics::DnsMetrics;
use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter};
use rdns::validation::AdmissionCheck;

use crate::ServeContext;

/// A query ACL listing `specs` and nobody else.
pub(crate) fn only(specs: &[&str]) -> crate::QueryAcl {
    let specs: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
    crate::QueryAcl::Only(Arc::new(
        rdns::security::TransferAcl::parse(&specs).expect("acl"),
    ))
}

/// A context whose query rate is `rate` per second with a burst of the same,
/// and whose other limits are off, so a test measures the thing it names.
pub(crate) fn context(rate: u32) -> ServeContext {
    ServeContext {
        limiter: Arc::new(RateLimiter::new(RateLimitConfig::per_second(rate, rate))),
        responses: Arc::new(ResponseLimiter::disabled()),
        admission: Arc::new(AdmissionCheck::with_defaults()),
        logger: Arc::new(QueryLogger::new()),
        metrics: Arc::new(DnsMetrics::new()),
        udp: rdns::UdpSizes::default(),
        per_source: crate::SourceConnections::default(),
        acl: crate::QueryAcl::Open,
        nsid: None,
        // A test that asserts on the rate limiter overrides this with a
        // `Clock::fixed`; the rest never read it.
        clock: Clock::system(),
    }
}

/// A minimal question: twelve octets of header and one question section.
///
/// Built by hand rather than through `rdns`: what the admission check reads is
/// octets, and a fixture that goes through the serializer would prove the
/// serializer.
pub(crate) fn query(id: u16) -> Vec<u8> {
    let mut packet = vec![0x00, 0x00]; // id, filled in below
    packet[..2].copy_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[
        0x00, 0x00, // QR=0, opcode QUERY
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    packet.extend_from_slice(b"\x07example\x03com\x00");
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
    packet
}

/// The id off the front of a message, which is how a test tells replies apart.
pub(crate) fn id_of(message: &[u8]) -> u16 {
    u16::from_be_bytes([message[0], message[1]])
}

/// A response to [`query`]: the same question, plus one A record at `ttl`.
///
/// Built by hand for the reason `query` is — a fixture that went through the
/// serializer would prove the serializer. This one exists so the DoH tests can
/// assert on `Cache-Control`, which RFC 8484 §5.1 takes from the smallest TTL
/// in the answer.
pub(crate) fn answer_with_ttl(id: u16, ttl: u32) -> Vec<u8> {
    let mut packet = id.to_be_bytes().to_vec();
    packet.extend_from_slice(&[
        0x81, 0x80, // QR=1, RD, RA
        0x00, 0x01, // one question
        0x00, 0x01, // one answer
        0x00, 0x00, 0x00, 0x00,
    ]);
    packet.extend_from_slice(b"\x07example\x03com\x00");
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
                                                         // The owner, as a pointer back to the question's name at offset 12.
    packet.extend_from_slice(&[0xc0, 0x0c]);
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
    packet.extend_from_slice(&ttl.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    packet.extend_from_slice(&[192, 0, 2, 10]);
    packet
}

/// What this thread logs from here until the guard drops, as text.
///
/// Thread-local, so a `#[tokio::test]` — current-thread by default — sees its
/// spawned tasks' lines and no other test's.
pub(crate) fn capture_logs() -> (
    Arc<std::sync::Mutex<Vec<u8>>>,
    tracing::subscriber::DefaultGuard,
) {
    #[derive(Clone)]
    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("a test thread panicked")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // With one scoped dispatcher alive, tracing-core 0.1.36 decides a callsite's
    // interest from the *registering* thread's default alone, so a line another
    // test's thread logs first is cached as disabled for the process — and is
    // then missing here. A second dispatcher, alive for the run, makes it ask
    // every one. Hit by #155's log test beside #161's and #162's.
    static SECOND: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    SECOND.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Sink(lines.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || sink.clone())
        .finish();
    (lines, tracing::subscriber::set_default(subscriber))
}
