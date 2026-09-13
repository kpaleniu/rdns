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

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

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
