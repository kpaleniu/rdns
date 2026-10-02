//! DoT, DoQ and DoH, configured once and bound once, for both daemons.
//!
//! Each daemon had checked the certificate pair, loaded the store, bound the
//! three listeners and spawned them with plain TCP in its own copy, and the
//! copies had drifted in policy: one checked the pair rule over the merged
//! view, the other per source, and `rdnsr` never named its listeners
//! (`TODO.md` #153). What differs between the daemons is a parameter: the
//! client anchors (`rdnsd`'s `--transfer-client-ca`) and the [`RateLimit`].
//!
//! Two values and not one function, because `--check-config` sits between
//! them (`CLAUDE.md` §15): [`Encrypted`] reads the certificate above the
//! dry-run exit and binds nothing; [`EncryptedListeners`] is bound below it.

use std::io;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use rdns::shutdown::Shutdown;
use rdns::tls_identity::TrustAnchors;

use crate::tcp::{self, Handler, RateLimit};
use crate::tls::CertificateStore;
use crate::{https, quic, tls, TransportLimits};

/// The encrypted listeners as the operator configured them, from the merged
/// view of flags and file.
pub struct EncryptedFlags<'a> {
    pub tls_listen: Option<&'a str>,
    pub quic_listen: Option<&'a str>,
    pub https_listen: Option<&'a str>,
    pub https_path: &'a str,
    pub tls_cert: Option<&'a Path>,
    pub tls_key: Option<&'a Path>,
}

/// Where to answer DNS over TLS, QUIC and HTTPS, and the certificate all three
/// present.
pub struct Encrypted {
    dot: Option<String>,
    doq: Option<String>,
    /// The address and the path.
    doh: Option<(String, String)>,
    /// One store for all three, shared with the reload path, so a renewal
    /// reaches every listener on a reload rather than a restart (`TODO.md`
    /// #42a). Two stores over the same files would be a certificate that
    /// expires on one port.
    store: Arc<CertificateStore>,
    /// Anchors a *client* certificate is verified against (`TODO.md` #59).
    /// `None` asks no client for one. Here rather than per listener because a
    /// transfer may arrive over any of the three.
    clients: Option<TrustAnchors>,
}

impl Encrypted {
    /// Check the pair rule and load the certificate. `None` when no encrypted
    /// listener is configured, whatever else is.
    ///
    /// The pair rule is in code rather than in clap's `requires`: any one of
    /// three listeners needs both files, which `requires` cannot say as an
    /// "or", and a config file has no `requires` at all. Without it, 853 binds
    /// and presents nothing. The message names keys, not flags, because by
    /// here the two sources are merged and which one set a field is gone.
    pub fn configure(
        flags: EncryptedFlags<'_>,
        clients: Option<TrustAnchors>,
    ) -> Result<Option<Encrypted>> {
        if flags.tls_listen.is_none() && flags.quic_listen.is_none() && flags.https_listen.is_none()
        {
            return Ok(None);
        }
        let (Some(cert), Some(key)) = (flags.tls_cert, flags.tls_key) else {
            return Err(anyhow!(
                "tls-listen, quic-listen and https-listen need both tls-cert and tls-key"
            ));
        };
        Ok(Some(Encrypted {
            dot: flags.tls_listen.map(str::to_string),
            doq: flags.quic_listen.map(str::to_string),
            doh: flags
                .https_listen
                .map(|addr| (addr.to_string(), flags.https_path.to_string())),
            store: CertificateStore::load(cert, key)?,
            clients,
        }))
    }

    /// "127.0.0.1:853 DoT, 127.0.0.1:853 DoQ", or whichever are configured.
    ///
    /// One spelling for the startup line and `--check-config`: the dry run had
    /// written its own copy that matched DoT and DoQ alone, so a DoH-only
    /// server was reported as "encrypted transports disabled" by the one
    /// command whose job is to be believed before a restart (`CLAUDE.md` §7).
    pub fn listeners(&self) -> String {
        let mut parts = Vec::new();
        if let Some(addr) = &self.dot {
            parts.push(format!("{addr} DoT"));
        }
        if let Some(addr) = &self.doq {
            parts.push(format!("{addr} DoQ"));
        }
        if let Some((addr, path)) = &self.doh {
            parts.push(format!("{addr}{path} DoH"));
        }
        parts.join(", ")
    }

    /// The listeners and the certificate's files, for the startup line.
    pub fn describe(&self) -> String {
        let (cert, key) = self.store.paths();
        format!(
            "{} (cert {}, key {})",
            self.listeners(),
            cert.display(),
            key.display()
        )
    }

    /// The store, for the daemon's reload path.
    pub fn store(&self) -> Arc<CertificateStore> {
        self.store.clone()
    }

    pub fn clients(&self) -> Option<&TrustAnchors> {
        self.clients.as_ref()
    }
}

/// The encrypted listeners, bound, with the limits they were bound under.
pub struct EncryptedListeners {
    dot: Option<(TcpListener, Arc<ServerConfig>)>,
    doh: Option<(TcpListener, https::Endpoint)>,
    doq: Option<quinn::Endpoint>,
    limits: TransportLimits,
}

impl EncryptedListeners {
    /// Bind every configured listener, or fail naming the flag.
    ///
    /// Bound before anything is announced, as the plain listeners are: a port
    /// conflict on 853 must stop the start rather than leave a server running
    /// that a DoT client cannot reach and nothing reports. `limits` is taken
    /// here because DoQ's stream and idle ceilings are transport parameters,
    /// fixed when its endpoint is built.
    pub async fn bind(
        config: Option<&Encrypted>,
        limits: TransportLimits,
    ) -> Result<EncryptedListeners> {
        let mut bound = EncryptedListeners {
            dot: None,
            doh: None,
            doq: None,
            limits,
        };
        let Some(config) = config else {
            return Ok(bound);
        };
        if let Some(addr) = &config.dot {
            bound.dot = Some((
                TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("--tls-listen {addr}"))?,
                tls::server_config(config.store.clone(), config.clients.clone())?,
            ));
        }
        if let Some((addr, path)) = &config.doh {
            bound.doh = Some((
                TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("--https-listen {addr}"))?,
                https::endpoint(config.store.clone(), path, config.clients.clone())?,
            ));
        }
        // quinn binds its own UDP socket, so the same rule for a different kind
        // of listener.
        if let Some(addr) = &config.doq {
            bound.doq = Some(
                quinn::Endpoint::server(
                    quic::server_config(config.store.clone(), limits, config.clients.clone())?,
                    addr.parse()
                        .with_context(|| format!("--quic-listen {addr} is not an address:port"))?,
                )
                .with_context(|| format!("--quic-listen {addr}"))?,
            );
        }
        Ok(bound)
    }

    /// Spawn plain TCP, already bound beside the UDP socket it shares an
    /// address with, and every bound encrypted listener into `loops`.
    ///
    /// One admission and one rate rule for all four: what TLS changes is who
    /// can read the connection, not what is answered on it.
    pub fn spawn<H: Handler>(
        self,
        plain: TcpListener,
        handler: Arc<H>,
        rate: RateLimit,
        shutdown: &Shutdown,
        loops: &mut JoinSet<Result<(), io::Error>>,
    ) {
        let EncryptedListeners {
            dot,
            doh,
            doq,
            limits,
        } = self;
        loops.spawn(tcp::serve(
            plain,
            handler.clone(),
            limits,
            rate,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
        if let Some((listener, config)) = dot {
            loops.spawn(tls::serve(
                listener,
                config,
                handler.clone(),
                limits,
                rate,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));
        }
        if let Some(endpoint) = doq {
            loops.spawn(quic::serve(
                endpoint,
                handler.clone(),
                limits,
                rate,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));
        }
        if let Some((listener, endpoint)) = doh {
            loops.spawn(https::serve(
                listener,
                endpoint,
                handler,
                limits,
                rate,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::testing::write_pem;

    fn flags<'a>(
        dot: Option<&'a str>,
        doh: Option<&'a str>,
        cert: Option<&'a Path>,
        key: Option<&'a Path>,
    ) -> EncryptedFlags<'a> {
        EncryptedFlags {
            tls_listen: dot,
            quic_listen: None,
            https_listen: doh,
            https_path: "/dns-query",
            tls_cert: cert,
            tls_key: key,
        }
    }

    #[test]
    fn no_listener_is_off_whatever_else_is_set() {
        let pem = write_pem("encrypted-off", "localhost");
        assert!(
            Encrypted::configure(flags(None, None, Some(&pem.cert), Some(&pem.key)), None)
                .expect("not an error")
                .is_none()
        );
    }

    /// Any one listener without both files is refused, in key terms.
    #[test]
    fn a_listener_needs_both_files() {
        let pem = write_pem("encrypted-pair", "localhost");
        for (cert, key) in [
            (None, None),
            (Some(pem.cert.as_path()), None),
            (None, Some(pem.key.as_path())),
        ] {
            let err = Encrypted::configure(flags(None, Some("127.0.0.1:443"), cert, key), None)
                .err()
                .expect("refused");
            assert_eq!(
                err.to_string(),
                "tls-listen, quic-listen and https-listen need both tls-cert and tls-key"
            );
        }
    }

    /// A DoH-only server is named as one, which is what the dry run once got
    /// wrong.
    #[test]
    fn the_listeners_are_named_doh_only_included() {
        let pem = write_pem("encrypted-name", "localhost");
        let doh = Encrypted::configure(
            flags(None, Some("127.0.0.1:443"), Some(&pem.cert), Some(&pem.key)),
            None,
        )
        .expect("loads")
        .expect("configured");
        assert_eq!(doh.listeners(), "127.0.0.1:443/dns-query DoH");

        let both = Encrypted::configure(
            flags(
                Some("127.0.0.1:853"),
                Some("127.0.0.1:443"),
                Some(&pem.cert),
                Some(&pem.key),
            ),
            None,
        )
        .expect("loads")
        .expect("configured");
        assert_eq!(
            both.listeners(),
            "127.0.0.1:853 DoT, 127.0.0.1:443/dns-query DoH"
        );
    }
}
