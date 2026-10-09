//! TSIG, RFC 8945: a DNS transaction authenticated with a shared secret.
//!
//! Its own crate because `rdnsc` signs a zone transfer and must not link a
//! server to do it (`TODO.md` #66c). Every `crate::` path in its production
//! code resolves to `rdns-core`, so only `ring` and `base64` come with it, and
//! `rdns-core` already carries the second.
//!
//! The module below is re-exported flat, so `rdns_tsig::TsigKey` is the path
//! and `rdns::tsig::TsigKey` is too.

// `TODO.md` #82b's ratchet; the reason is at the top of `rdns/src/lib.rs`.
#![warn(unreachable_pub)]
// `push_str(&format!(..))` allocates a `String` to copy it; `write!` into the
// target does not. Off by default (restriction group).
#![warn(clippy::format_push_string)]

mod tsig;

pub use tsig::*;
