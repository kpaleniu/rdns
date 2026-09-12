//! Fixtures shared by this crate's two test modules.
//!
//! `lib.rs` had them and `tcp.rs` could not see them, which is `TODO.md` #38e
//! one module further in.

use std::sync::Arc;

use rdns::logging::QueryLogger;
use rdns::metrics::DnsMetrics;
use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter};
use rdns::validation::AdmissionCheck;

use crate::ServeContext;

/// A context whose query rate is `rate` per second with a burst of the same,
/// and whose other limits are off, so a test measures the thing it names.
pub(crate) fn context(rate: u32) -> ServeContext {
    ServeContext {
        limiter: Arc::new(RateLimiter::new(RateLimitConfig::per_second(rate, rate))),
        responses: Arc::new(ResponseLimiter::disabled()),
        validator: Arc::new(AdmissionCheck::with_defaults()),
        logger: Arc::new(QueryLogger::new()),
        metrics: Arc::new(DnsMetrics::new()),
        udp: rdns::UdpSizes::default(),
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
