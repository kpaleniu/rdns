//! `addr[:port][#keyname]` — one spelling for "another DNS server, and the key
//! to talk to it with".
//!
//! Two flags name a peer this way. `--secondary zone@addr[:port][#key]` says
//! where a zone is replicated *from*; `--also-notify addr[:port][#key]` says
//! who is told when it changes. They were not one parser until `TODO.md` #46,
//! and the cost was exactly what `CLAUDE.md` §7 predicts: `--secondary` grew
//! the `#key` half and `--also-notify` did not, so a transfer could be
//! authenticated while the notification that triggers it could not be — and a
//! secondary whose notify ACL names a key refused every one of them.
//!
//! The `#key` is a *name*, resolved against the keyring `--tsig-key` builds, so
//! a secret is written down once ([`crate::tsig::TsigKeyring::by_name`]).

use std::net::{IpAddr, SocketAddr};

use crate::error::{ConfigError, ConfigResult};

/// Split `addr[:port][#keyname]` into its two halves.
///
/// `spec` is the whole original text and is only used in error messages, so
/// that a bad `--secondary` complains about what the operator typed rather than
/// about the fragment left after the zone was split off.
pub(crate) fn parse_endpoint(text: &str, spec: &str) -> ConfigResult<(SocketAddr, Option<String>)> {
    let (addr, key_name) = match text.split_once('#') {
        Some((addr, key)) if !key.trim().is_empty() => (addr, Some(key.trim().to_string())),
        Some(_) => {
            return Err(ConfigError::new(format!(
                "{spec:?}: '#' with no key name after it"
            )))
        }
        None => (text, None),
    };
    Ok((parse_address(addr.trim(), spec)?, key_name))
}

/// `addr` or `addr:port`, defaulting to 53.
///
/// A bare IPv6 address has colons of its own, so `[::1]:5353` is the only
/// unambiguous way to give one a port — which is what `SocketAddr` already
/// parses, so the shape is the familiar one rather than a new convention.
fn parse_address(text: &str, spec: &str) -> ConfigResult<SocketAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    match text.parse::<IpAddr>() {
        Ok(ip) => Ok(SocketAddr::new(ip, 53)),
        Err(e) => Err(ConfigError::new(format!(
            "{spec:?}: {text:?} is not an address or address:port: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> (SocketAddr, Option<String>) {
        parse_endpoint(text, text).expect("parses")
    }

    #[test]
    fn a_bare_address_gets_port_53_and_no_key() {
        assert_eq!(
            ok("192.0.2.1"),
            ("192.0.2.1:53".parse().unwrap(), None),
            "53 is the port a NOTIFY and a transfer both default to"
        );
    }

    #[test]
    fn a_port_may_be_given() {
        assert_eq!(ok("192.0.2.1:5353").0, "192.0.2.1:5353".parse().unwrap());
    }

    /// The reason the port is bracketed rather than separated some other way.
    #[test]
    fn an_ipv6_address_needs_brackets_to_carry_a_port() {
        assert_eq!(ok("::1").0, "[::1]:53".parse().unwrap());
        assert_eq!(ok("[::1]:5353").0, "[::1]:5353".parse().unwrap());
    }

    #[test]
    fn a_key_name_may_follow_a_hash() {
        assert_eq!(
            ok("192.0.2.1#transfer.key."),
            (
                "192.0.2.1:53".parse().unwrap(),
                Some("transfer.key.".to_string())
            )
        );
        assert_eq!(
            ok("[::1]:5353#k.").1,
            Some("k.".to_string()),
            "a key may follow a bracketed address with a port"
        );
    }

    /// A trailing `#` is a typo, not a request for no key: the operator meant to
    /// authenticate and would otherwise not see that they had not.
    #[test]
    fn a_hash_with_no_name_is_refused() {
        assert!(parse_endpoint("192.0.2.1#", "192.0.2.1#").is_err());
        assert!(parse_endpoint("192.0.2.1#  ", "192.0.2.1#  ").is_err());
    }

    #[test]
    fn a_name_that_is_not_an_address_is_refused() {
        let err = parse_endpoint("ns1.example.com", "ns1.example.com")
            .expect_err("a hostname is not resolved here");
        assert!(err.to_string().contains("is not an address"), "got: {err}");
    }
}
