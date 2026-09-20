//! DNS above the wire: zones, DNSSEC, transfers, the resolver, and the
//! operational furniture a daemon runs on.
//!
//! The wire format itself — messages, records, names, compression, admission
//! and the control protocol — is [`rdns_core`], which has no `tokio` and no
//! crypto so that a client can link it alone (`TODO.md` #31). Everything core
//! defines is re-exported here, so `rdns::DnsMessage` still names what it
//! always did and nothing downstream has two spellings to choose between.

// `TODO.md` #82b's ratchet. #38's sweep asked "is this item *named* from
// outside" and had no compiler behind it, so it did not hold: `pub` in this
// crate went 694 → 889 over the 168 commits after #38 was filed, `pub(crate)`
// 17 → 21. This lint asks the weaker question rustc can answer — is the item
// reachable from outside at all — which is what caught `xfr.rs`'s five `pub fn`
// on two private assemblers. It does not answer #38's question; that sweep has
// to be re-run by hand.
#![warn(unreachable_pub)]

pub use rdns_core::*;

// The presentation format is its own crate since `TODO.md` #66a, so that a
// client can render a record without linking a server. Re-exported under the
// paths it had, because 11 modules here name them and none of them cares which
// crate the encodings live in.
pub use rdns_present::record_text;
// `persist` is `rdns-core`'s since `TODO.md` #66c: writing a file a reader
// cannot catch half-written, and refusing to read a secret anyone can, are
// things a *client* needs too. Re-exported under the path it had.
pub use rdns_core::persist;
pub use rdns_present::{denial_wire, svcb};
pub use rdns_tsig as tsig;

#[cfg(test)]
mod bench;
pub mod cache;
pub mod catalog;
pub mod config;
pub mod dns64;
pub mod dnssec;
pub mod dnssec_answer;
pub mod dnssec_chain;
pub mod dnssec_denial;
pub mod dnssec_key;
/// Real DNSSEC signing, for tests only.
#[cfg(test)]
mod dnssec_test_util;
pub mod dnssec_validation_mode;
pub mod dnstap;
mod endpoint;
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
pub mod readiness;
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
pub mod zone_signer;
pub mod zone_writer;

pub use cache::{CacheStats, DnsCache};
