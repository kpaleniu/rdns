//! XFR over TLS (RFC 9103): the client half, which is the half a secondary is.
//!
//! The server half is not here and is not new. A transfer is framed DNS
//! (RFC 1035 §4.2.2) whichever socket carries it, so `rdns_transport::tls`'s
//! DoT listener already answers an AXFR — what `rdnsd` gained for this is a
//! *policy*, not a protocol: `--transfer-tls-only` refuses one that arrives in
//! clear. This module is the outgoing side, where there was nothing at all.
//!
//! **Why the client TLS lives in `rdns` and the server TLS in `rdns-transport`.**
//! The client half of a transfer has always been here — [`crate::xfr`] opens
//! its own socket — and `rdns-transport` is the accept loops both daemons
//! share. It also could not be the other way round: `rdns-transport` depends on
//! this crate. Measured before writing it: `rustls` and `tokio-rustls` here are
//! **+0 runtime packages**, because `rdns-transport` already links both and
//! cargo resolves one copy.
//!
//! What RFC 9103 asks of a client, and where each is:
//!
//! - **§7.1**: the ALPN token `dot` "MUST be selected in the TLS handshake" —
//!   `ALPN_DOT`, the same token the DoT listener advertises.
//! - **§7.2**: "All implementations of this specification MUST use only TLS 1.3
//!   \[RFC8446\] or later" — [`XotTrust::from_ca_file`] builds the configuration
//!   with `TLS13` and nothing else, which is *narrower* than the DoT listener,
//!   where RFC 7858 still permits 1.2 for a stub resolver.
//! - **§7.3**: "The connection for XoT SHOULD be established using port 853" —
//!   [`XOT_PORT`], the default when `+tls=` is given and no port is.
//! - **§7.5**: "The client MUST authenticate the server by use of an
//!   authentication domain name using a Strict Privacy profile, as described in
//!   \[RFC8310\]" — hence [`XotName`], which is required rather than optional.
//!   There is no opportunistic mode here on purpose: an unauthenticated TLS
//!   connection is exactly as forgeable as the cleartext it replaces, while
//!   looking in a log like it is not.
//!
//! **Trust anchors are a file the operator names**, and nothing else. A system
//! trust store would be `rustls-native-certs` or `webpki-roots`, which is a
//! dependency (`CLAUDE.md` §14) for a relationship that is almost always
//! private: a primary and its own secondaries. An operator whose primary holds
//! a publicly issued certificate points `--transfer-tls-ca` at the system
//! bundle, which is a PEM file like any other.
//!
//! **No client certificate.** §7.5 lets a server validate its client by "mutual
//! TLS (mTLS)" or by "an IP-based ACL ... combined with a valid TSIG/SIG(0)
//! signature", and this tree does the second — it has had both halves of it
//! since `security::TransferAcl` and `TODO.md` #16. The consequence is an
//! interop limit rather than a conformance one, and it is `TODO.md` #51.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::{ConfigError, ConfigResult, TransferError, TransferResult};

/// The port RFC 9103 §7.3 says an XoT connection SHOULD use, which is
/// RFC 7858's.
pub const XOT_PORT: u16 = 853;

/// The ALPN token RFC 9103 §7.1 requires be selected.
const ALPN_DOT: &[u8] = b"dot";

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

impl std::fmt::Display for XotName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// The trust anchors every XoT connection this server makes is verified
/// against, and the TLS settings RFC 9103 fixes.
///
/// One per process: the anchors are an operator's decision about who issues
/// certificates, not about one master. Clone is an `Arc`.
#[derive(Clone, Debug)]
pub struct XotTrust {
    config: Arc<ClientConfig>,
    /// Kept beside the configuration because rustls does not hand the root
    /// store back once the verifier has it, and the banner should say how many
    /// anchors an operator actually loaded.
    anchors: usize,
}

impl XotTrust {
    /// Read a PEM bundle of certificate authorities and build the client
    /// configuration from it.
    ///
    /// An empty file is refused rather than loaded: a `RootCertStore` with
    /// nothing in it verifies nothing, so it would start, and then fail every
    /// handshake with a message about the master (`CLAUDE.md` §4).
    pub fn from_ca_file(path: &Path) -> ConfigResult<Self> {
        use rustls::pki_types::pem::PemObject;

        let mut roots = RootCertStore::empty();
        let certs = CertificateDer::pem_file_iter(path).map_err(|e| {
            ConfigError::new(format!(
                "reading the transfer trust anchors {}: {e}",
                path.display()
            ))
        })?;
        for cert in certs {
            let cert = cert.map_err(|e| {
                ConfigError::new(format!(
                    "parsing the transfer trust anchors {}: {e}",
                    path.display()
                ))
            })?;
            roots.add(cert).map_err(|e| {
                ConfigError::new(format!(
                    "{} holds a certificate that cannot be a trust anchor: {e}",
                    path.display()
                ))
            })?;
        }
        if roots.is_empty() {
            return Err(ConfigError::new(format!(
                "{} holds no CERTIFICATE block: an empty anchor set loads and \
                 then refuses every master's certificate",
                path.display()
            )));
        }
        let anchors = roots.len();
        Ok(XotTrust {
            config: Arc::new(client_config(roots)),
            anchors,
        })
    }

    /// How many anchors were loaded, for the startup banner.
    pub fn anchor_count(&self) -> usize {
        self.anchors
    }
}

/// TLS 1.3 and nothing else (§7.2), ALPN `dot` (§7.1), and the operator's
/// anchors (§7.5).
fn client_config(roots: RootCertStore) -> ClientConfig {
    // `builder_with_protocol_versions` rather than `builder`: the workspace
    // turns rustls's `tls12` feature on for the DoT *listener*, where RFC 7858
    // still allows 1.2 and a stub resolver in the field may offer nothing else.
    // A transfer is the other case, and §7.2 is a MUST.
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        // §7.5's other authorization method is mTLS; this tree uses the IP ACL
        // and TSIG it names beside it. See the module docs and `TODO.md` #51.
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_DOT.to_vec()];
    config
}

/// One master reached over TLS: the anchors, and the name its certificate must
/// carry.
#[derive(Clone, Debug)]
pub struct XotClient {
    trust: XotTrust,
    name: XotName,
}

impl XotClient {
    pub fn new(trust: XotTrust, name: XotName) -> Self {
        XotClient { trust, name }
    }

    /// The name the certificate is checked against, for a log line.
    pub fn name(&self) -> &XotName {
        &self.name
    }

    /// Connect and complete the handshake.
    ///
    /// The failure is an [`io::Error`], which is what `tokio-rustls` returns
    /// and what a caller of this already handles. Not its own
    /// [`TransferError`] variant: nothing branches on one, and §3's rule is
    /// that a variant nobody matches on is a `String` with extra syntax. What
    /// is added is the context — which master, and which name it failed to
    /// present — because "invalid peer certificate: UnknownIssuer" on its own
    /// names neither.
    pub(crate) async fn connect(&self, addr: SocketAddr) -> TransferResult<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await.map_err(|e| {
            TransferError::Io(io::Error::new(
                e.kind(),
                format!("connecting to {addr} for XoT: {e}"),
            ))
        })?;
        let connector = TlsConnector::from(self.trust.config.clone());
        connector
            .connect(self.name.name.clone(), tcp)
            .await
            .map_err(|e| {
                TransferError::Io(io::Error::new(
                    e.kind(),
                    format!("the TLS handshake with {addr} as {} failed: {e}", self.name),
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_parsed_once_and_kept_as_written() {
        let name = XotName::parse("ns1.example.com.").expect("a domain name");
        assert_eq!(name.to_string(), "ns1.example.com.");
    }

    /// RFC 9103 §7.5 makes authenticating the server a MUST, so there is no
    /// spelling of "TLS, but do not check who answered".
    #[test]
    fn an_empty_name_is_refused_with_the_reason() {
        let err = XotName::parse("  ").expect_err("no name");
        assert!(
            err.to_string().contains("authenticate the master by name"),
            "the error should say why a name is required: {err}"
        );
    }

    #[test]
    fn a_name_with_a_slash_in_it_is_not_a_name() {
        assert!(XotName::parse("ns1.example.com/foo").is_err());
    }

    /// An IP literal is a `ServerName` rustls can check against an IP SAN, so
    /// it parses. Written down because it looks like it should not.
    #[test]
    fn an_address_is_a_name_rustls_will_check_against_an_ip_san() {
        assert!(XotName::parse("192.0.2.1").is_ok());
    }

    #[test]
    fn an_empty_anchor_file_is_refused_rather_than_loaded() {
        let path = std::env::temp_dir().join(format!(
            "rdns-xot-empty-{}-{}.pem",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, "# no certificates here\n").expect("write");
        let err = XotTrust::from_ca_file(&path).expect_err("an empty bundle");
        assert!(
            err.to_string().contains("no CERTIFICATE block"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_anchor_file_names_the_path() {
        let path = std::env::temp_dir().join("rdns-xot-nonexistent.pem");
        let _ = std::fs::remove_file(&path);
        let err = XotTrust::from_ca_file(&path).expect_err("no such file");
        assert!(
            err.to_string().contains("rdns-xot-nonexistent.pem"),
            "unexpected error: {err}"
        );
    }
}
