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
