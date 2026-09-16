//! A TLS identity read from PEM: a certificate chain and the key that goes
//! with it.
//!
//! One module because there are two of these and they are the same job. The
//! DoT/DoQ/DoH listener presents one to its clients
//! (`rdns_transport::tls::CertificateStore`); an XoT client presents one to a
//! master that asks for mutual TLS ([`crate::xot`], RFC 9103 §7.5). Written
//! separately they would drift over the three things that are easy to leave out
//! and each produce a server that starts and then fails every handshake: an
//! empty chain, a key file anyone can read, and a key that is not the chain's
//! (`CLAUDE.md` §7).
//!
//! A pair rather than two loose readers, because a chain without its key is not
//! a thing a caller can do anything with. What this module does *not* do is
//! check the two go together: both callers get that from rustls —
//! `CertifiedKey::from_der` and `with_client_auth_cert` both run `keys_match`,
//! and asking a third time here would be a second copy of a check that already
//! has a home.

use std::path::Path;

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;

use crate::error::{ConfigError, ConfigResult};

/// A certificate chain and its private key, both read from PEM files.
#[derive(Debug)]
pub struct TlsIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl TlsIdentity {
    /// Read both files, refusing an empty chain and a key anyone can read.
    ///
    /// `what` names the pair for the error message — "the TLS certificate", "the
    /// transfer client certificate" — because an operator with both configured
    /// needs the error to say which one is wrong.
    pub fn from_files(cert_path: &Path, key_path: &Path, what: &str) -> ConfigResult<Self> {
        use rustls::pki_types::pem::PemObject;

        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
            .map_err(|e| ConfigError::new(format!("reading {what} {}: {e}", cert_path.display())))?
            .collect::<Result<_, _>>()
            .map_err(|e| {
                ConfigError::new(format!("parsing {what} {}: {e}", cert_path.display()))
            })?;
        if chain.is_empty() {
            return Err(ConfigError::new(format!(
                "{} holds no CERTIFICATE block: an empty chain loads and then fails \
                 every handshake",
                cert_path.display()
            )));
        }

        // The same check the DNSSEC key loader and a TSIG `secret-file` get
        // (`CLAUDE.md` §15): a key restored from backup as 0644, or `chmod -R`'d
        // by a deploy script, is the ordinary way a private key stops being
        // private. Unix only, and `ensure_private` says so rather than letting
        // "the permissions were checked" be a claim true on one platform.
        crate::persist::ensure_private(key_path, "a TLS private key")
            .map_err(|e| ConfigError::new(format!("{}: {e}", key_path.display())))?;
        let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
            ConfigError::new(format!(
                "reading the private key for {what} {}: {e}",
                key_path.display()
            ))
        })?;

        Ok(TlsIdentity { chain, key })
    }

    /// The chain and the key, for whichever rustls builder wants them.
    pub fn into_parts(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (self.chain, self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("rdns-tls-identity-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// An empty chain loads in rustls and fails every handshake afterwards, so
    /// it is refused where the file name is still in hand.
    #[test]
    fn a_certificate_file_with_no_certificate_in_it_is_refused() {
        let cert = scratch("empty.pem");
        let key = scratch("empty.key");
        std::fs::write(&cert, "# nothing here\n").expect("write");
        std::fs::write(&key, "# nothing here\n").expect("write");

        let err =
            TlsIdentity::from_files(&cert, &key, "a test certificate").expect_err("an empty chain");
        assert!(
            err.to_string().contains("no CERTIFICATE block"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }

    /// The error names the file and what it was being read as: an operator with
    /// a listener certificate *and* a transfer client certificate has two of
    /// these, and "reading the certificate" names neither.
    #[test]
    fn a_missing_file_is_named_along_with_what_it_was_for() {
        let cert = scratch("absent.pem");
        let err = TlsIdentity::from_files(&cert, &cert, "the transfer client certificate")
            .expect_err("no such file");
        let text = err.to_string();
        assert!(text.contains("absent.pem"), "{text}");
        assert!(text.contains("the transfer client certificate"), "{text}");
    }
}

/// The certificate authorities a peer's certificate is checked against, read
/// from one PEM bundle.
///
/// Both directions need this and they used to read it separately: an XoT
/// *client* checking a master's certificate ([`crate::xot::XotTrust`]) and,
/// since `TODO.md` #59, a primary checking a transfer client's. The empty-file
/// refusal is the reason it is one function — an anchor set with nothing in it
/// loads, starts, and then refuses every handshake with a message about the
/// other end (`CLAUDE.md` §4, §7).
///
/// A newtype rather than a bare `Arc<RootCertStore>` so that a caller outside
/// this crate can hold one without naming `rustls`, and so the count survives:
/// rustls does not hand the store back once a verifier has it, and the startup
/// banner should say how many anchors an operator actually loaded.
#[derive(Debug, Clone)]
pub struct TrustAnchors {
    roots: Arc<RootCertStore>,
}

impl TrustAnchors {
    /// Read a PEM bundle. `what` names it for the error message, because an
    /// operator with anchors on both ends needs to know which file is wrong.
    pub fn from_ca_file(path: &Path, what: &str) -> ConfigResult<TrustAnchors> {
        use rustls::pki_types::pem::PemObject;

        let mut roots = RootCertStore::empty();
        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|e| ConfigError::new(format!("reading {what} {}: {e}", path.display())))?;
        for cert in certs {
            let cert = cert
                .map_err(|e| ConfigError::new(format!("parsing {what} {}: {e}", path.display())))?;
            roots.add(cert).map_err(|e| {
                ConfigError::new(format!(
                    "{} holds a certificate that cannot be a trust anchor: {e}",
                    path.display()
                ))
            })?;
        }
        if roots.is_empty() {
            return Err(ConfigError::new(format!(
                "{} holds no CERTIFICATE block: an empty anchor set loads and then \
                 refuses every certificate it is asked about",
                path.display()
            )));
        }
        Ok(TrustAnchors {
            roots: Arc::new(roots),
        })
    }

    /// How many anchors were loaded, for the startup banner.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The store itself, for the rustls configuration that will hold it.
    pub fn store(&self) -> Arc<RootCertStore> {
        self.roots.clone()
    }
}
