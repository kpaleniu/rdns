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
//! **A client certificate is optional and off by default.** §7.5 lets a server
//! validate its client by "mutual TLS (mTLS)" or by "an IP-based ACL ...
//! combined with a valid TSIG/SIG(0) signature", and adds "If only one method
//! is selected, then mTLS is preferred". As a *server* this tree does the
//! second and has since `security::TransferAcl` and `TODO.md` #16; as a
//! *client* it will now present a certificate when the operator names one
//! (`--transfer-tls-cert`/`--transfer-tls-key`), which is what replicating from
//! a primary that demands mTLS needs. Off by default because a certificate sent
//! to a master that did not ask for one is not sent at all — rustls offers it
//! only in response to a CertificateRequest — but configuring one that does not
//! exist should be a sentence at startup rather than a handshake failure later
//! (`CLAUDE.md` §15).
//!
//! The mirror image — *this* server demanding a certificate from a transfer
//! client — is `TODO.md` #59, and is not the same size: verifying a certificate
//! answers who a peer is and says nothing about which zones it may take
//! (`CLAUDE.md` §16).

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
use crate::tls_identity::TlsIdentity;

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
    /// Whether an identity was configured. Read back from the configuration
    /// would be better, and rustls hands back a `ResolvesClientCert` that
    /// cannot answer it without a `ClientHello` to ask about.
    presenting: bool,
    /// Kept beside the configuration because rustls does not hand the root
    /// store back once the verifier has it, and the banner should say how many
    /// anchors an operator actually loaded.
    anchors: usize,
}

impl XotTrust {
    /// Read a PEM bundle of certificate authorities and build the client
    /// configuration from it.
    ///
    /// `identity` is the certificate this server presents when a master asks
    /// for one (§7.5's mTLS); `None` is the ordinary case and means the master
    /// authorizes by address and TSIG.
    ///
    /// An empty file is refused rather than loaded: a `RootCertStore` with
    /// nothing in it verifies nothing, so it would start, and then fail every
    /// handshake with a message about the master (`CLAUDE.md` §4).
    pub fn from_ca_file(path: &Path, identity: Option<TlsIdentity>) -> ConfigResult<Self> {
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
        let presenting = identity.is_some();
        Ok(XotTrust {
            config: Arc::new(client_config(roots, identity)?),
            anchors,
            presenting,
        })
    }

    /// How many anchors were loaded, for the startup banner.
    pub fn anchor_count(&self) -> usize {
        self.anchors
    }

    /// Whether a client certificate will be offered, for the startup banner.
    ///
    /// Said out loud because a master that stops asking for one, or never asked,
    /// makes mTLS silently not in force — a policy the operator believes is
    /// applied and is not (`CLAUDE.md` §4). What this claims is only that a
    /// certificate is loaded and will be offered if asked.
    pub fn presents_a_certificate(&self) -> bool {
        self.presenting
    }
}

/// TLS 1.3 and nothing else (§7.2), ALPN `dot` (§7.1), the operator's anchors
/// and, when one is configured, the certificate this client presents (§7.5).
fn client_config(
    roots: RootCertStore,
    identity: Option<TlsIdentity>,
) -> ConfigResult<ClientConfig> {
    // `builder_with_protocol_versions` rather than `builder`: the workspace
    // turns rustls's `tls12` feature on for the DoT *listener*, where RFC 7858
    // still allows 1.2 and a stub resolver in the field may offer nothing else.
    // A transfer is the other case, and §7.2 is a MUST.
    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots);
    let mut config = match identity {
        // Fallible, and the failures are worth catching at startup: rustls
        // loads the key here and runs `keys_match` against the chain, so a pair
        // that does not go together, or a key this build cannot sign with, is a
        // sentence on stderr rather than every transfer failing on a timer.
        Some(identity) => {
            let (chain, key) = identity.into_parts();
            builder.with_client_auth_cert(chain, key).map_err(|e| {
                ConfigError::new(format!(
                    "the transfer client certificate and its key cannot be used together: {e}"
                ))
            })?
        }
        // §7.5's other authorization method is mTLS; a master that does not ask
        // for a certificate authorizes by the IP ACL and TSIG it names beside
        // it. See the module docs.
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![ALPN_DOT.to_vec()];
    Ok(config)
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
        let err = XotTrust::from_ca_file(&path, None).expect_err("an empty bundle");
        assert!(
            err.to_string().contains("no CERTIFICATE block"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A pair, on disk, with the key at the mode `ensure_private` insists on.
    fn issued(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("rdns-xot-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let issued =
            rcgen::generate_simple_self_signed(vec!["ns1.example.com".to_string()]).expect("cert");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, issued.cert.pem()).expect("write cert");
        std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        (cert, key)
    }

    /// The client half of RFC 9103 §7.5's mTLS: a certificate is configured,
    /// loads, and is what the banner reports.
    #[test]
    fn a_client_certificate_is_loaded_and_said_out_loud() {
        let (cert, key) = issued("mtls");
        let identity =
            TlsIdentity::from_files(&cert, &key, "the transfer client certificate").expect("pair");
        // The same self-signed certificate doubles as the anchor file: what is
        // under test is the client identity, not who the master is.
        let trust = XotTrust::from_ca_file(&cert, Some(identity)).expect("anchors and identity");
        assert!(trust.presents_a_certificate());
        assert_eq!(trust.anchor_count(), 1);

        let without = XotTrust::from_ca_file(&cert, None).expect("anchors");
        assert!(!without.presents_a_certificate());
    }

    /// A chain and a key that are not a pair load happily on their own and then
    /// fail every handshake. rustls runs `keys_match` inside
    /// `with_client_auth_cert`, so the failure is at startup — which is the
    /// whole reason the identity is built there rather than per connection.
    #[test]
    fn a_certificate_and_a_key_that_are_not_a_pair_are_refused_at_startup() {
        let (cert, _) = issued("mismatch-a");
        let (_, other_key) = issued("mismatch-b");
        let identity =
            TlsIdentity::from_files(&cert, &other_key, "the transfer client certificate")
                .expect("both files read");
        let err = XotTrust::from_ca_file(&cert, Some(identity)).expect_err("not a pair");
        assert!(
            err.to_string().contains("cannot be used together"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_missing_anchor_file_names_the_path() {
        let path = std::env::temp_dir().join("rdns-xot-nonexistent.pem");
        let _ = std::fs::remove_file(&path);
        let err = XotTrust::from_ca_file(&path, None).expect_err("no such file");
        assert!(
            err.to_string().contains("rdns-xot-nonexistent.pem"),
            "unexpected error: {err}"
        );
    }
}
