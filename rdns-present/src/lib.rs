//! The text presentation format, and the wire encodings it needs.
//!
//! Between [`rdns_core`], which is the message on the wire, and `rdns`, which
//! is everything a server does with one. What lives here is the half of the
//! format that a *client* needs as much as a server does: rendering a record as
//! the line a zone file writes it on, and the encodings that line is spelled in
//! — canonical name order (RFC 4034 §6.1), type bitmaps (§4.1.2), base32hex
//! (RFC 4648 §7), SVCB parameters (RFC 9460 §2.1) and the `YYYYMMDDHHmmSS` an
//! RRSIG carries.
//!
//! `TODO.md` #66a and #67. The reason it is a crate and not a module of `rdns`
//! is `rdnsc`: it transfers a zone correctly today and prints the records with
//! `{:?}`, and the alternative — depending on `rdns` — measured at +38 packages
//! and +385 KB on a binary of 814 KB, because that crate means `tokio`,
//! `rustls` and `ring` whatever the caller touches.
//!
//! No crypto and no runtime, by construction: the one dependency is
//! `rdns-core`. A hash *value* of a fixed length lives here
//! ([`denial_wire::Nsec3Hash`]); everything that computes one is `rdns`'s.

pub mod denial_wire;
pub mod dnssec_time;
pub mod record_text;
pub mod svcb;
