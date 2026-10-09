//! DNS above the wire: zones, DNSSEC, transfers, the resolver, and the
//! operational furniture a daemon runs on.
//!
//! The wire format itself — messages, records, names, compression, admission
//! and the control protocol — is [`rdns_core`], which has no `tokio` and no
//! crypto so that a client can link it alone (`TODO.md` #31). Everything core
//! defines is re-exported here, so `rdns::DnsMessage` still names what it
//! always did and nothing downstream has two spellings to choose between.

// `TODO.md` #82b's ratchet: rustc answers whether an item is reachable from
// outside, not whether it is named there (#38), which is re-run by hand.
#![warn(unreachable_pub)]
// `push_str(&format!(..))` allocates a `String` to copy it; `write!` into the
// target does not. Off by default (restriction group).
#![warn(clippy::format_push_string)]

pub use rdns_core::*;

/// Allocator calls tallied per thread, so a unit test here can count what one
/// call costs — the resolver's fixtures are private to this crate's tests.
/// `rdnsr`'s reason holds: `System`, a pass-through plus one thread-local
/// increment for every other test in this binary.
#[cfg(test)]
#[global_allocator]
static ALLOC: testutil::Counting<std::alloc::System> = testutil::Counting(std::alloc::System);

// Its own crate, so a client renders records without a server; re-exported for
// this crate's modules.
pub use rdns_present::record_text;
// `rdns-core`'s, as atomic writes and private secrets are a client's need too;
// re-exported.
pub use rdns_core::persist;
pub use rdns_present::{denial_wire, svcb};
pub use rdns_tsig as tsig;

#[cfg(test)]
mod bench;
pub mod cache;
pub mod catalog;
pub mod config;
/// Cache expiry arithmetic, `pub(crate)` for the reason [`eviction`] is.
mod deadline;
pub mod dns64;
pub mod dnssec;
pub mod dnssec_chain;
pub mod dnssec_denial;
pub mod dnssec_key;
/// Real DNSSEC signing, for tests only.
#[cfg(test)]
mod dnssec_test_util;
pub mod dnssec_validation_mode;
pub mod dnstap;
pub mod endpoint;
pub mod error;
/// Shared eviction, `pub(crate)` because it is a mechanism and not a policy.
mod eviction;
pub mod ixfr;
pub mod journal;
pub mod logging;
pub mod metrics;
pub mod negative_cache;
pub mod notify;
pub mod nsec_cache;
pub mod nta;
pub mod peer;
pub mod resolver;
pub mod rfc5011;
pub mod rpz;
pub mod secondary;
pub mod security;
pub mod shutdown;
pub mod special_names;
/// Plain record fixtures, for tests only.
#[cfg(test)]
mod test_records;
pub mod tls_identity;
pub mod transfer;
pub mod update;
pub mod xfr;
pub mod xot;
pub mod zone;
pub mod zone_answer;
pub mod zone_signer;
pub mod zone_writer;

pub use cache::{CacheStats, DnsCache};
