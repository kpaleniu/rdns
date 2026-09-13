//! DNS over TLS (RFC 7858): the same TCP loop, behind a handshake.
//!
//! The protocol half is nearly nothing, and that is the point of doing it here.
//! RFC 7858 §3.3 is "the DNS message is sent as in RFC 1035 §4.2.2", a 2-octet
//! length prefix and the message — which [`crate::tcp`] already reads and writes
//! — so what this module adds is a handshake, a certificate, and the ALPN token.
//! [`crate::tcp::serve_one`] does the rest, generic over
//! [`crate::tcp::SplitStream`].
//!
//! **What is not the protocol, and is the actual work** (`TODO.md` #42a): where
//! the certificate comes from, whether a renewed one is picked up without a
//! restart, and what happens when it expires.
//!
//! - **Where it comes from**: two PEM files an operator names. Nothing is
//!   generated, and nothing is fetched — an ACME client is a different program,
//!   and `TODO.md` #43d has `rdnsd` answering one already.
//! - **A renewed one**: [`CertificateStore`] is the `ResolvesServerCert` rustls
//!   asks per handshake, and it re-reads both files on reload. So a renewal is
//!   `certbot --deploy-hook 'rdnsctl reload'`, or a SIGHUP, and not a restart.
//!   A reload that cannot read the new files **keeps the old certificate** and
//!   says so: half a renewal must not take the listener down.
//! - **Expiry is deliberately not parsed here.** Reading `notAfter` means an
//!   X.509 parser, and the only one this tree would gain is a dependency whose
//!   entire job is a log line (`CLAUDE.md` §14). What an expired certificate
//!   produces is a handshake every client rejects, and *that* is observable
//!   without parsing anything: `dns_tls_handshake_failures_total` is the series
//!   to alert on, and it is the symptom rather than a prediction of it.
//!
//! **No client certificates.** RFC 8310 §8.2 describes mutual TLS for DoT and
//! it authenticates a *client*, which is not a thing an authoritative server or
//! an open resolver has an opinion about. TSIG is how this tree says who a peer
//! is, and it works on every transport rather than one. A *transfer* is the one
//! case where RFC 9103 §7.5 names mTLS as an alternative, and asking for a
//! client certificate here would ask every DoT querier for one as well: the
//! server half of that is `TODO.md` #59, and `rdns::xot` is the client half.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Context, Result};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use rdns::shutdown::{Busy, Stop};
use rdns::tls_identity::TlsIdentity;

use crate::tcp::{Handler, RateLimit, SplitStream};
use crate::TransportLimits;
use rdns::validation::{Arrival, TlsVersion};

/// The port RFC 7858 §3.1 assigns.
pub const DOT_PORT: u16 = 853;

/// The ALPN token RFC 7858 §6 registers.
///
/// Advertised, not required. A client that offers no ALPN at all is accepted —
/// rustls only fails the handshake when a client offers a list and none of it
/// matches — because DoT predates the token and stub resolvers in the field
/// still connect without it.
const ALPN_DOT: &[u8] = b"dot";

impl SplitStream for TlsStream<TcpStream> {
    type Reader = tokio::io::ReadHalf<TlsStream<TcpStream>>;
    type Writer = tokio::io::WriteHalf<TlsStream<TcpStream>>;

    fn split_halves(self) -> (Self::Reader, Self::Writer) {
        tokio::io::split(self)
    }
}

/// The certificate and key, swappable while the server runs.
///
/// rustls asks [`ResolvesServerCert::resolve`] once per handshake, which is what
/// makes a renewal a reload rather than a restart. The lock is held for the
/// clone of one `Arc` and never across any I/O.
pub struct CertificateStore {
    cert_path: PathBuf,
    key_path: PathBuf,
    current: RwLock<Arc<CertifiedKey>>,
}

impl std::fmt::Debug for CertificateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateStore")
            .field("cert", &self.cert_path)
            .field("key", &self.key_path)
            .finish()
    }
}

impl CertificateStore {
    /// Read both files, or say which one and why.
    ///
    /// Failing here stops the server, which is the rule a configured listener
    /// already follows: `--metrics-listen` with a port that will not bind stops
    /// the start rather than silently disabling itself, and a TLS listener that
    /// cannot present a certificate is the same case. BIND, Knot and Unbound all
    /// refuse to start on an unreadable `tls` certificate too.
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
        let certified = read_certified_key(cert_path, key_path)?;
        Ok(Arc::new(CertificateStore {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            current: RwLock::new(certified),
        }))
    }

    /// Re-read both files and install the result.
    ///
    /// The old certificate survives a failure, and the caller is told. A renewal
    /// that half-wrote its files must not take DoT off the air — the running
    /// certificate is still valid until it is not, and an operator can fix the
    /// files without a window where nothing answers on 853.
    pub fn reload(&self) -> Result<()> {
        let certified = read_certified_key(&self.cert_path, &self.key_path)
            .context("the TLS certificate was not replaced")?;
        match self.current.write() {
            Ok(mut guard) => {
                *guard = certified;
                Ok(())
            }
            // Never panic while holding a lock, and never on a path a reload
            // reaches (`CLAUDE.md` §6). A poisoned lock here means a previous
            // writer panicked, which cannot happen above — but if it did, the
            // old certificate is still being served and saying so beats
            // poisoning every later handshake.
            Err(_) => Err(anyhow!(
                "the certificate lock is poisoned; still serving the previously \
                 loaded certificate"
            )),
        }
    }

    /// What the files are, for the startup banner.
    pub fn paths(&self) -> (&Path, &Path) {
        (&self.cert_path, &self.key_path)
    }
}

impl ResolvesServerCert for CertificateStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // One certificate, whatever was asked for: SNI-based selection is a
        // virtual-hosting feature, and a DNS server is reached by address.
        //
        // `read()` rather than `unwrap()`: this runs per handshake, and a
        // poisoned lock must not turn into a panic in a connection task.
        // `None` here is a handshake failure, which is what the counter is for.
        self.current.read().ok().map(|guard| guard.clone())
    }
}

/// Load a certificate chain and its key, and check they go together.
fn read_certified_key(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>> {
    let (certs, key) =
        TlsIdentity::from_files(cert_path, key_path, "the TLS certificate")?.into_parts();
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| {
        anyhow!(
            "{}: the private key is not one this build can sign with: {e}",
            key_path.display()
        )
    })?;
    // `CertifiedKey::new` does not check that the key matches the certificate,
    // so ask for the signer here: a mismatched pair otherwise loads, starts, and
    // fails every handshake.
    let certified = CertifiedKey::new(certs, signing_key);
    certified.keys_match().map_err(|e| {
        anyhow!(
            "{} and {} are not a pair: {e}",
            cert_path.display(),
            key_path.display()
        )
    })?;
    Ok(Arc::new(certified))
}

/// The rustls configuration a DoT listener serves under.
pub fn server_config(store: Arc<CertificateStore>) -> Result<Arc<ServerConfig>> {
    Ok(Arc::new(config_with_alpn(store, ALPN_DOT)))
}

/// The same configuration under a different ALPN token.
///
/// DoQ is the other caller (`TODO.md` #42b): same certificate, same store, same
/// reload — a different protocol on top. Shared so that a certificate renewal
/// reaches both listeners, which it would not if each built its own.
pub(crate) fn config_with_alpn(store: Arc<CertificateStore>, alpn: &[u8]) -> ServerConfig {
    let mut config = ServerConfig::builder()
        // A DoT or DoQ *server* authenticates itself to the client and does not
        // ask the client to authenticate. See the module docs.
        .with_no_client_auth()
        .with_cert_resolver(store);
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

/// Accept TLS connections and serve each one as an ordinary DNS-over-TCP
/// session, until told to stop.
///
/// The same shape as [`crate::tcp::serve`] and deliberately not a copy of it in
/// the part that matters: once the handshake is done the connection is handed to
/// [`crate::tcp::serve_one`], which is the loop that already reads framed
/// messages, admits them and answers concurrently.
pub async fn serve<H: Handler>(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    handler: Arc<H>,
    limits: TransportLimits,
    rate: RateLimit,
    stop: Stop,
    busy: Busy,
) -> Result<(), io::Error> {
    let acceptor = TlsAcceptor::from(config);
    let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = stop.wait() => return Ok(()),
        };
        if rate == RateLimit::PerConnection
            && !handler
                .context()
                .allow_source(peer.ip(), handler.context().clock.now())
        {
            continue;
        }
        let Ok(permit) = permits.clone().acquire_owned().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        let handler = handler.clone();
        let stop = stop.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            // The handshake happens *here*, inside the connection's own task,
            // and not in the accept loop above. A TLS handshake is two round
            // trips with a stranger, so doing it before the spawn would let one
            // slow or malicious peer hold up every other connection — the
            // accept-loop equivalent of the stall RFC 7766 §6.2.1.1 avoids
            // within a connection.
            let stream = tokio::select! {
                accepted = acceptor.accept(stream) => accepted,
                // A handshake that has not finished by shutdown is a client that
                // has been told nothing yet, so there is nothing to drain.
                _ = stop.wait() => {
                    drop(permit);
                    drop(busy);
                    return;
                }
            };
            match stream {
                Ok(stream) => {
                    serve_one_tls(stream, peer, handler, limits, rate, stop).await;
                }
                Err(e) => {
                    // DEBUG, not WARN. Port 853 is scanned, an expired
                    // certificate makes every client hang up here, and a
                    // protocol-version mismatch looks the same as both — none
                    // of which is worth a log line each at the default level.
                    // The counter is what an operator alerts on.
                    handler
                        .context()
                        .metrics
                        .count(&handler.context().metrics.tls_handshake_failures);
                    tracing::debug!(peer = %peer.ip(), "TLS handshake failed: {e}");
                }
            }
            drop(permit);
            drop(busy);
        });
    }
}

/// Serve one connection whose handshake is already done.
///
/// Separate so a caller with its own accept loop — a test, say — can drive a
/// single session, matching [`crate::tcp::serve_one`].
pub async fn serve_one_tls<H: Handler>(
    stream: TlsStream<TcpStream>,
    peer: std::net::SocketAddr,
    handler: Arc<H>,
    limits: TransportLimits,
    rate: RateLimit,
    stop: Stop,
) {
    handler
        .context()
        .metrics
        .count(&handler.context().metrics.tls_handshakes);
    // Read from the finished handshake rather than assumed from the listener:
    // this build offers TLS 1.2 as well, because RFC 7858 §4.1 asks only for
    // "1.2 or later" and a stub resolver in the field may offer nothing else.
    // A *transfer* needs 1.3 (RFC 9103 §7.2), and only the connection knows
    // which it got.
    let arrival = Arrival::Dot(match stream.get_ref().1.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => TlsVersion::Tls13,
        _ => TlsVersion::Older,
    });
    crate::tcp::serve_one(stream, peer, handler, limits, rate, arrival, stop).await;
}

/// Fixtures the DoT and DoQ tests share.
///
/// `pub(crate)` and not `#[cfg(test)]`-private to this module, because
/// `quic.rs` needs the same certificate and the alternative was a second copy
/// of it (`CLAUDE.md` §7) — which is how the two would come to disagree about
/// what "a valid pair" means.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A certificate and key on disk, generated per run.
    ///
    /// Generated rather than checked in: a private key in the tree is a private
    /// key in every clone, and a fixture with an expiry date is a test that
    /// starts failing on a Tuesday years from now.
    pub(crate) struct Pem {
        dir: std::path::PathBuf,
        pub(crate) cert: PathBuf,
        pub(crate) key: PathBuf,
        pub(crate) der: Vec<u8>,
    }

    impl Drop for Pem {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    pub(crate) fn write_pem(tag: &str, name: &str) -> Pem {
        // A counter as well as the pid, and it is not belt-and-braces: three DoH
        // tests reused one tag, so they shared a directory, wrote cert.pem and
        // key.pem over each other and loaded a mismatched pair. The `Drop` below
        // then deleted a directory another test was still using. Unique per
        // call, so reusing a tag cannot do that again.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rdns-tls-{tag}-{}-{serial}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let issued =
            rcgen::generate_simple_self_signed(vec![name.to_string()]).expect("a certificate");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, issued.cert.pem()).expect("write cert");
        std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write key");
        make_private(&key);
        Pem {
            der: issued.cert.der().to_vec(),
            dir,
            cert,
            key,
        }
    }

    /// The mode `ensure_private` insists on. A no-op where there are no mode
    /// bits, which is the same platform split the check itself has.
    pub(crate) fn make_private(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 0600");
        }
        #[cfg(not(unix))]
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{make_private, write_pem};
    use super::*;
    use crate::testutil::{context, query};
    use crate::ServeContext;
    use rdns::shutdown::Shutdown;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    struct Echo(ServeContext, std::sync::Mutex<Option<Arrival>>);

    impl Echo {
        fn new(ctx: ServeContext) -> Echo {
            Echo(ctx, std::sync::Mutex::new(None))
        }

        /// What the last message handled arrived over.
        fn seen(&self) -> Option<Arrival> {
            *self.1.lock().expect("the test's own mutex")
        }
    }

    impl Handler for Echo {
        fn context(&self) -> &ServeContext {
            &self.0
        }

        async fn handle(
            &self,
            packet: Vec<u8>,
            _peer: SocketAddr,
            _now: u64,
            arrival: Arrival,
            out: mpsc::Sender<crate::tcp::Reply>,
        ) {
            *self.1.lock().expect("the test's own mutex") = Some(arrival);
            crate::tcp::send_framed(&out, &packet).await;
        }
    }

    /// A client that trusts exactly the certificate the server was given.
    fn client_config(server_der: &[u8]) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(server_der.to_vec()))
            .expect("the self-signed certificate is a valid root");
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    /// The whole of 42a in one test: a real handshake, then an ordinary
    /// length-prefixed DNS message over it (RFC 7858 §3.3), answered by the same
    /// `tcp::serve_one` the plain transport uses.
    #[tokio::test]
    async fn a_dot_client_completes_a_handshake_and_gets_an_answer() {
        let pem = write_pem("handshake", "localhost");
        let store = CertificateStore::load(&pem.cert, &pem.key).expect("loads");
        let config = server_config(store).expect("a server config");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let shutdown = Shutdown::new();
        let handler = Arc::new(Echo::new(context(0)));
        let metrics = handler.0.metrics.clone();
        let seen = handler.clone();
        let server = tokio::spawn(serve(
            listener,
            config,
            handler,
            TransportLimits::default(),
            RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let connector = tokio_rustls::TlsConnector::from(client_config(&pem.der));
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("a name");
        let mut tls = connector.connect(name, tcp).await.expect("the handshake");

        let question = query(0x4242);
        tls.write_all(&rdns::framed(&question).expect("frames"))
            .await
            .expect("send");

        let mut prefix = [0u8; 2];
        tls.read_exact(&mut prefix).await.expect("length prefix");
        let mut body = vec![0u8; u16::from_be_bytes(prefix) as usize];
        tls.read_exact(&mut body).await.expect("body");
        assert_eq!(body, question, "the message came back over TLS unchanged");

        assert_eq!(
            metrics
                .tls_handshakes
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the completed handshake is counted"
        );
        assert_eq!(
            metrics
                .tls_handshake_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        // What the handler was told the connection was, read off the finished
        // handshake rather than assumed from the listener. `rdnsd` refuses a
        // zone transfer that is not this (RFC 9103 §7.2, §11), so a listener
        // reporting the wrong thing would refuse every transfer or accept every
        // one.
        assert_eq!(
            seen.seen(),
            Some(Arrival::Dot(TlsVersion::Tls13)),
            "a DoT connection this build negotiates is TLS 1.3"
        );

        shutdown.begin();
        server.abort();
    }

    /// A client that will not trust the certificate fails the handshake, and the
    /// failure is counted rather than logged at a level nobody reads.
    ///
    /// This is the series an expired certificate shows up in — nothing here
    /// parses `notAfter`, so the counter is the whole story (see the module
    /// docs).
    #[tokio::test]
    async fn a_handshake_that_fails_is_counted() {
        let pem = write_pem("failure", "localhost");
        let other = write_pem("failure-other", "localhost");
        let store = CertificateStore::load(&pem.cert, &pem.key).expect("loads");
        let config = server_config(store).expect("a server config");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let shutdown = Shutdown::new();
        let handler = Arc::new(Echo::new(context(0)));
        let metrics = handler.0.metrics.clone();
        let server = tokio::spawn(serve(
            listener,
            config,
            handler,
            TransportLimits::default(),
            RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        // Trusting a different self-signed certificate, so the server's does not
        // chain to anything this client knows.
        let connector = tokio_rustls::TlsConnector::from(client_config(&other.der));
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("a name");
        assert!(
            connector.connect(name, tcp).await.is_err(),
            "an untrusted certificate must not complete a handshake"
        );

        // The server notices on its own schedule; give the task a moment.
        for _ in 0..50 {
            if metrics
                .tls_handshake_failures
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            metrics
                .tls_handshake_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "dns_tls_handshake_failures_total is what an operator alerts on"
        );
        assert_eq!(
            metrics
                .tls_handshakes
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "and a failed handshake is not also counted as a completed one"
        );

        shutdown.begin();
        server.abort();
    }

    /// The renewal story: new files at the same paths, one reload, new
    /// certificate — without a restart and without dropping the listener.
    #[test]
    fn a_reload_picks_up_a_renewed_certificate() {
        let pem = write_pem("renew", "localhost");
        let store = CertificateStore::load(&pem.cert, &pem.key).expect("loads");
        let before = served_der(&store);
        assert_eq!(before, pem.der, "serving what was loaded");

        // A renewal is new bytes at the same two paths, which is what every ACME
        // client writes.
        let renewed =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("a cert");
        std::fs::write(&pem.cert, renewed.cert.pem()).expect("write cert");
        std::fs::write(&pem.key, renewed.signing_key.serialize_pem()).expect("write key");
        make_private(&pem.key);

        store.reload().expect("the renewed pair loads");
        let after = served_der(&store);
        assert_ne!(after, before, "the reload installed the new certificate");
        assert_eq!(after, renewed.cert.der().to_vec());
    }

    /// A renewal that half-wrote its files must not take the listener down: the
    /// certificate already being served is still valid, and an operator can fix
    /// the files without a window where 853 answers nothing.
    #[test]
    fn a_failed_reload_keeps_the_certificate_it_was_serving() {
        let pem = write_pem("keep", "localhost");
        let store = CertificateStore::load(&pem.cert, &pem.key).expect("loads");
        let before = served_der(&store);

        std::fs::write(&pem.cert, "-----BEGIN CERTIFICATE-----\nnot base64\n")
            .expect("write rubbish");
        let err = store.reload().expect_err("a cert that will not parse");
        assert!(
            err.to_string().contains("not replaced"),
            "the message says the old one is still in force: {err}"
        );
        assert_eq!(
            served_der(&store),
            before,
            "and it is: the handshake keeps working"
        );
    }

    /// A certificate and a key that are not a pair load happily and then fail
    /// every handshake, which is the worst way to find out. Caught at load.
    #[test]
    fn a_certificate_and_key_that_do_not_match_are_refused() {
        let one = write_pem("pair-a", "localhost");
        let two = write_pem("pair-b", "localhost");
        let err = CertificateStore::load(&one.cert, &two.key).expect_err("a mismatched pair");
        assert!(err.to_string().contains("not a pair"), "got: {err:#}");
    }

    #[test]
    fn an_empty_certificate_file_is_refused_rather_than_loaded() {
        let pem = write_pem("empty", "localhost");
        std::fs::write(&pem.cert, "# no certificate here\n").expect("write");
        let err = CertificateStore::load(&pem.cert, &pem.key).expect_err("no CERTIFICATE block");
        assert!(err.to_string().contains("no CERTIFICATE"), "got: {err:#}");
    }

    /// The same rule the DNSSEC keys and a TSIG `secret-file` get
    /// (`CLAUDE.md` §15). Unix only, and the test says so rather than letting
    /// "the permissions were checked" be a claim that is true on one platform.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_private_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let pem = write_pem("mode", "localhost");
        std::fs::set_permissions(&pem.key, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");
        let err = CertificateStore::load(&pem.cert, &pem.key).expect_err("a readable key");
        assert!(err.to_string().contains("not a secret"), "got: {err:#}");
    }

    /// What `resolve` would hand a client, as DER.
    fn served_der(store: &CertificateStore) -> Vec<u8> {
        let resolved = store
            .current
            .read()
            .expect("the lock is not poisoned in a test");
        resolved.cert[0].to_vec()
    }
}
