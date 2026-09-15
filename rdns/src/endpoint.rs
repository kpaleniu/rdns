//! `addr[:port][#keyname][+tls=name]` — one spelling for "another DNS server,
//! and how to talk to it".
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
//!
//! `+tls=name` is XFR over TLS (`TODO.md` #44d): fetch this zone over TLS and
//! require the master's certificate to carry that name. It is last, and the
//! name is not optional — RFC 9103 §7.5 makes authenticating the server a MUST,
//! so there is deliberately no spelling of "encrypt but do not check"
//! ([`crate::xot`]). Only `--secondary` accepts it; the [`Endpoint`] a
//! `--also-notify` parses to carries the field, and `NotifyTarget::parse`
//! refuses it rather than accepting a flag that would do nothing.

use std::net::{IpAddr, SocketAddr};

use crate::error::{ConfigError, ConfigResult};
use rustls_pki_types::ServerName;

/// The port RFC 9103 §7.3 says an XoT connection SHOULD use, which is
/// RFC 7858's.
pub const XOT_PORT: u16 = 853;

/// The name a master's certificate has to carry, and the SNI sent to it.
///
/// RFC 8310 §6.1 calls this the authentication domain name. A newtype rather
/// than a `String` because it is parsed once, at startup, where a bad one is a
/// sentence on stderr instead of a transfer that fails on a timer months later
/// (`CLAUDE.md` §15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XotName {
    name: ServerName<'static>,
    /// What the operator wrote, for messages: `ServerName`'s own rendering
    /// lower-cases and normalizes, and an error should quote the flag.
    text: String,
}

impl XotName {
    pub fn parse(text: &str) -> ConfigResult<Self> {
        let text = text.trim();
        if text.is_empty() {
            return Err(ConfigError::new(
                "+tls= with no name after it: RFC 9103 §7.5 has the client \
                 authenticate the master by name, so there is no name to check \
                 the certificate against",
            ));
        }
        let name = ServerName::try_from(text.to_owned()).map_err(|e| {
            ConfigError::new(format!(
                "{text:?} is not a name a certificate can be checked against: {e}"
            ))
        })?;
        Ok(XotName {
            name,
            text: text.to_owned(),
        })
    }
}

impl XotName {
    /// The checked name, for the one caller that opens a connection with it.
    ///
    /// `pub(crate)` rather than public: what a caller outside this crate has
    /// business with is the name it wrote, which `Display` gives.
    pub(crate) fn server_name(&self) -> ServerName<'static> {
        self.name.clone()
    }
}

impl std::fmt::Display for XotName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// One peer, parsed.
///
/// A struct rather than a tuple since the third field: two `Option`s of
/// different meaning next to each other in a return type is how a caller ends
/// up reading the key as the name (`CLAUDE.md` §17).
#[derive(Debug)]
pub(crate) struct Endpoint {
    pub(crate) addr: SocketAddr,
    pub(crate) key_name: Option<String>,
    /// `Some` when `+tls=` was given: the name the master's certificate must
    /// carry.
    pub(crate) tls: Option<XotName>,
}

/// Split `addr[:port][#keyname][+tls=name]` into its parts.
///
/// `spec` is the whole original text and is only used in error messages, so
/// that a bad `--secondary` complains about what the operator typed rather than
/// about the fragment left after the zone was split off.
///
/// The suffixes come off in the order they are written, last first. A key name
/// is a domain name and a `+` in one would be perverse, so splitting there
/// cannot take a bite out of the key — and `addr+tls=n#key`, the other order,
/// is refused rather than guessed at.
pub(crate) fn parse_endpoint(text: &str, spec: &str) -> ConfigResult<Endpoint> {
    let (rest, tls) = match text.split_once("+tls=") {
        Some((rest, name)) => {
            if name.contains('#') {
                return Err(ConfigError::new(format!(
                    "{spec:?}: the key goes before the '+tls=', as \
                     addr[:port][#key][+tls=name]"
                )));
            }
            (
                rest,
                Some(XotName::parse(name).map_err(|e| ConfigError::new(format!("{spec:?}: {e}")))?),
            )
        }
        None => (text, None),
    };
    let (addr, key_name) = match rest.split_once('#') {
        Some((addr, key)) if !key.trim().is_empty() => (addr, Some(key.trim().to_string())),
        Some(_) => {
            return Err(ConfigError::new(format!(
                "{spec:?}: '#' with no key name after it"
            )))
        }
        None => (rest, None),
    };
    // RFC 9103 §7.3: "The connection for XoT SHOULD be established using port
    // 853". A stated port still wins — §7.3 allows "mutual agreement between
    // the primary and secondary to use a port other than port 853".
    let default_port = if tls.is_some() { XOT_PORT } else { 53 };
    Ok(Endpoint {
        addr: parse_address(addr.trim(), spec, default_port)?,
        key_name,
        tls,
    })
}

/// `addr` or `addr:port`, defaulting to `default_port`.
///
/// A bare IPv6 address has colons of its own, so `[::1]:5353` is the only
/// unambiguous way to give one a port — which is what `SocketAddr` already
/// parses, so the shape is the familiar one rather than a new convention.
fn parse_address(text: &str, spec: &str, default_port: u16) -> ConfigResult<SocketAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    match text.parse::<IpAddr>() {
        Ok(ip) => Ok(SocketAddr::new(ip, default_port)),
        Err(e) => Err(ConfigError::new(format!(
            "{spec:?}: {text:?} is not an address or address:port: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> (SocketAddr, Option<String>) {
        let parsed = parse_endpoint(text, text).expect("parses");
        (parsed.addr, parsed.key_name)
    }

    fn tls_of(text: &str) -> Option<XotName> {
        parse_endpoint(text, text).expect("parses").tls
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

    /// RFC 9103 §7.3: port 853 unless somebody says otherwise, and the port a
    /// spec states is somebody saying otherwise.
    #[test]
    fn tls_moves_the_default_port_to_853_and_a_stated_port_still_wins() {
        assert_eq!(
            ok("192.0.2.1+tls=ns1.example.com.").0,
            "192.0.2.1:853".parse().unwrap()
        );
        assert_eq!(
            ok("192.0.2.1:5853+tls=ns1.example.com.").0,
            "192.0.2.1:5853".parse().unwrap()
        );
        assert_eq!(ok("192.0.2.1").0, "192.0.2.1:53".parse().unwrap());
    }

    #[test]
    fn a_key_and_a_tls_name_can_both_be_given() {
        let parsed = parse_endpoint(
            "192.0.2.1#transfer.key.+tls=ns1.example.com.",
            "192.0.2.1#transfer.key.+tls=ns1.example.com.",
        )
        .expect("parses");
        assert_eq!(parsed.addr, "192.0.2.1:853".parse().unwrap());
        assert_eq!(parsed.key_name.as_deref(), Some("transfer.key."));
        assert_eq!(
            parsed.tls.map(|n| n.to_string()).as_deref(),
            Some("ns1.example.com.")
        );
    }

    /// The other order is refused rather than read as a key name with a `+` in
    /// it, which is what a lenient split would do.
    #[test]
    fn the_key_goes_before_the_tls_name() {
        let spec = "192.0.2.1+tls=ns1.example.com.#transfer.key.";
        let err = parse_endpoint(spec, spec).expect_err("the wrong order");
        assert!(
            err.to_string().contains("the key goes before"),
            "got: {err}"
        );
    }

    /// There is no "encrypt but do not check who answered": RFC 9103 §7.5 makes
    /// authenticating the master a MUST, so the name is the whole point of the
    /// suffix.
    #[test]
    fn tls_with_no_name_is_refused() {
        let err = parse_endpoint("192.0.2.1+tls=", "192.0.2.1+tls=").expect_err("no name");
        assert!(
            err.to_string().contains("authenticate the master"),
            "got: {err}"
        );
    }

    #[test]
    fn without_the_suffix_there_is_no_tls() {
        assert!(tls_of("192.0.2.1#transfer.key.").is_none());
    }
}
