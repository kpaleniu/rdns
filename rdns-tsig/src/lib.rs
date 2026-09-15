//! TSIG, RFC 8945: a DNS transaction authenticated with a shared secret.
//!
//! Its own crate since `TODO.md` #66c, because `rdnsc` signs a zone transfer
//! and must not link a server to do it. That this was possible at all is 67d's
//! measurement: every `crate::` path in this module's production code resolved
//! to `rdns-core`, so there was nothing to untangle — only `ring` and `base64`
//! come with it, and `rdns-core` already carries the second.
//!
//! The module below is re-exported flat, so `rdns_tsig::TsigKey` is the path
//! and `rdns::tsig::TsigKey` still is too.

mod tsig;

pub use tsig::*;
