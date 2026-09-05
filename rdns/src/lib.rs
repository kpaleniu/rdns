//! DNS above the wire: zones, DNSSEC, transfers, the resolver, and the
//! operational furniture a daemon runs on.
//!
//! The wire format itself — messages, records, names, compression, admission
//! and the control protocol — is [`rdns_core`], which has no `tokio` and no
//! crypto so that a client can link it alone (`TODO.md` #31). Everything core
//! defines is re-exported here, so `rdns::DnsMessage` and `rdns::utils` still
//! name what they always did and nothing downstream has two spellings to
//! choose between.

pub use rdns_core::*;

#[cfg(test)]
mod bench;
pub mod cache;
pub mod denial_wire;
pub mod dnssec;
pub mod dnssec_answer;
pub mod dnssec_chain;
pub mod dnssec_denial;
pub mod dnssec_key;
/// Real DNSSEC signing, for tests only.
#[cfg(test)]
mod dnssec_test_util;
pub mod dnssec_validation_mode;
pub mod error;
/// Shared eviction, `pub(crate)` because it is a mechanism and not a policy.
mod eviction;
pub mod ixfr;
pub mod journal;
pub mod logging;
pub mod metrics;
pub mod metrics_server;
pub mod negative_cache;
pub mod notify;
pub mod nsec_cache;
pub mod persist;
pub mod readiness;
pub mod resolver;
pub mod rfc5011;
pub mod secondary;
pub mod security;
pub mod shutdown;
pub mod special_names;
pub mod transfer;
pub mod tsig;
pub mod update;
pub mod xfr;
pub mod zone;
pub mod zone_signer;
pub mod zone_writer;

pub use cache::{CacheStats, DnsCache};
