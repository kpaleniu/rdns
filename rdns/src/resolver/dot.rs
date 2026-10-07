//! DNS over TLS to a forwarder (RFC 7858, `TODO.md` #175): one persistent,
//! pipelined connection per server.
//!
//! - Strict profile only (RFC 8310 §5): the certificate is checked against
//!   the server's authentication name and the operator's anchors, TLS 1.3,
//!   ALPN `dot` — [`TlsClientTrust`], the settings XoT uses. A failed
//!   handshake makes the server unreachable for this exchange; there is no
//!   cleartext fallback.
//! - Pipelined (§3.3, "clients SHOULD pipeline"): each query takes an ID not
//!   pending on the connection, and a response is matched by ID *and*
//!   question (§3.3, "MUST match the QNAME, QCLASS, and QTYPE").
//! - What the server can provoke (`CLAUDE.md` §4): a response matching no
//!   pending ID is dropped and counted, the connection kept; one whose
//!   question does not match its ID closes the connection, since the stream
//!   can no longer be trusted to pair answers with questions.
//! - Idle close after [`DEFAULT_IDLE`], or the server's own RFC 7828 timeout
//!   when it sends one. Every query asks for it.

use super::*;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::{oneshot, Notify};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::endpoint::AuthName;
use crate::metrics::DnsMetrics;
use crate::xot::TlsClientTrust;

/// How long a connection with nothing pending stays open when the server
/// names no keepalive. `rdnsd`'s own idle default, and well under Unbound's
/// 30 s `tcp-idle-timeout`: a forwarder holds connections from every client.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(10);

/// RFC 8467 §4.1(1): "Clients SHOULD pad queries to the closest multiple of
/// 128 octets."
const QUERY_PADDING_BLOCK: usize = 128;

/// The servers asked over TLS and what they are checked against.
#[derive(Clone)]
pub struct DotConfig {
    pub trust: TlsClientTrust,
    /// Keyed by address: TLS is a property of a server, which every route
    /// naming it shares — the caller refuses one address written both ways.
    pub servers: HashMap<SocketAddr, AuthName>,
}

impl std::fmt::Debug for DotConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotConfig")
            .field("anchors", &self.trust.anchor_count())
            .field("servers", &self.servers)
            .finish()
    }
}

/// The query as it goes over TLS: asking for the server's keepalive
/// (RFC 7828 §3.2.1, empty in a query) and padded (RFC 8467 §4.1(1)). Both
/// need the OPT `build_query` always ends the message with.
pub(super) fn tls_query(out: &OutgoingQuery) -> OutgoingQuery {
    let mut buf = out.buf.clone();
    crate::response::append_option(&mut buf, crate::EDNS_OPTION_TCP_KEEPALIVE, &[]);
    let pad = (buf.len() + 4).div_ceil(QUERY_PADDING_BLOCK) * QUERY_PADDING_BLOCK - buf.len() - 4;
    crate::response::append_option(&mut buf, crate::EDNS_OPTION_PADDING, &vec![0; pad]);
    OutgoingQuery {
        buf,
        id: out.id,
        qname: out.qname.clone(),
        qtype: out.qtype,
        qclass: out.qclass,
    }
}

pub(super) struct DotClients {
    trust: TlsClientTrust,
    servers: HashMap<SocketAddr, Server>,
    metrics: DnsMetrics,
}

struct Server {
    name: AuthName,
    /// A `tokio` mutex, held across the handshake: queries that arrive while
    /// one is under way wait for it rather than opening their own.
    slot: tokio::sync::Mutex<Option<Arc<Connection>>>,
}

impl DotClients {
    pub(super) fn new(config: DotConfig, metrics: DnsMetrics) -> DotClients {
        DotClients {
            trust: config.trust,
            servers: config
                .servers
                .into_iter()
                .map(|(addr, name)| {
                    let slot = tokio::sync::Mutex::new(None);
                    (addr, Server { name, slot })
                })
                .collect(),
            metrics,
        }
    }

    pub(super) fn serves(&self, addr: &SocketAddr) -> bool {
        self.servers.contains_key(addr)
    }

    /// One query, one reply. `timeout` bounds the whole exchange, connect and
    /// handshake included.
    pub(super) async fn exchange(
        &self,
        addr: SocketAddr,
        out: &OutgoingQuery,
        timeout: Duration,
    ) -> ResolveResult<Vec<u8>> {
        let Some(server) = self.servers.get(&addr) else {
            return Err(ResolveError::no_response(format!(
                "{addr} has no TLS configuration"
            )));
        };
        tokio::time::timeout(timeout, self.ask(addr, server, out, timeout))
            .await
            .unwrap_or_else(|_| {
                Err(ResolveError::no_response(format!(
                    "{addr} over TLS did not answer in time"
                )))
            })
    }

    async fn ask(
        &self,
        addr: SocketAddr,
        server: &Server,
        out: &OutgoingQuery,
        timeout: Duration,
    ) -> ResolveResult<Vec<u8>> {
        let conn = self.connection(addr, server, timeout).await?;
        let (waiting, reply) = conn.register(out)?;
        let mut bytes = out.buf.clone();
        bytes[..2].copy_from_slice(&waiting.id.to_be_bytes());
        if let Err(e) = conn.send(&bytes).await {
            conn.closing.notify_one();
            return Err(ResolveError::no_response(format!(
                "sending to {addr} over TLS: {e}"
            )));
        }
        let mut reply = reply.await.map_err(|_| {
            ResolveError::no_response(format!("the TLS connection to {addr} closed"))
        })?;
        drop(waiting);
        // Back to the ID the resolver chose, which is what it checks.
        reply[..2].copy_from_slice(&out.id.to_be_bytes());
        Ok(reply)
    }

    async fn connection(
        &self,
        addr: SocketAddr,
        server: &Server,
        timeout: Duration,
    ) -> ResolveResult<Arc<Connection>> {
        let mut slot = server.slot.lock().await;
        if let Some(conn) = slot.as_ref().filter(|c| !c.is_closed()) {
            return Ok(conn.clone());
        }
        let tcp = TcpStream::connect(addr).await?;
        let connector = TlsConnector::from(self.trust.client_config());
        let tls =
            match tokio::time::timeout(timeout, connector.connect(server.name.server_name(), tcp))
                .await
            {
                Ok(Ok(tls)) => tls,
                failed => {
                    self.metrics
                        .upstream_tls_handshake_failures
                        .fetch_add(1, Ordering::Relaxed);
                    let why = match failed {
                        Ok(Err(e)) => e.to_string(),
                        _ => "timed out".to_string(),
                    };
                    // WARN: an expired certificate at the forwarder otherwise
                    // shows only as SERVFAIL.
                    tracing::warn!("TLS handshake with {addr} as {} failed: {why}", server.name);
                    return Err(ResolveError::no_response(format!(
                        "TLS handshake with {addr} as {} failed: {why}",
                        server.name
                    )));
                }
            };
        let (reader, writer) = tokio::io::split(tls);
        let conn = Arc::new(Connection {
            writer: tokio::sync::Mutex::new(Some(writer)),
            state: Mutex::new(State {
                pending: HashMap::new(),
                closed: false,
                idle: DEFAULT_IDLE,
                last_used: Instant::now(),
            }),
            closing: Notify::new(),
        });
        tokio::spawn(read_loop(conn.clone(), reader, self.metrics.clone(), addr));
        *slot = Some(conn.clone());
        Ok(conn)
    }

    /// Close every connection: the shutdown drain is over and nothing will
    /// ask again.
    pub(super) async fn close_all(&self) {
        for server in self.servers.values() {
            if let Some(conn) = server.slot.lock().await.take() {
                conn.closing.notify_one();
            }
        }
    }
}

struct Connection {
    /// `None` once closed.
    writer: tokio::sync::Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>,
    state: Mutex<State>,
    closing: Notify,
}

struct State {
    pending: HashMap<u16, Pending>,
    closed: bool,
    idle: Duration,
    last_used: Instant,
}

struct Pending {
    qname: Name,
    qtype: Qtype,
    qclass: QueryClass,
    reply: oneshot::Sender<Vec<u8>>,
}

/// An ID held on a connection, given back when the exchange ends however it
/// ends — a timeout drops the future and this with it.
struct Waiting<'a> {
    conn: &'a Connection,
    id: u16,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.conn.state().pending.remove(&self.id);
    }
}

/// What one frame from the server was.
enum Delivered {
    Answered,
    Unmatched,
    /// Unparseable, or a question that is not its ID's: close.
    Broken,
}

impl Connection {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // Every update is a whole insert or remove; a panic elsewhere leaves
        // nothing half-done to protect.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is_closed(&self) -> bool {
        self.state().closed
    }

    fn register(
        &self,
        out: &OutgoingQuery,
    ) -> ResolveResult<(Waiting<'_>, oneshot::Receiver<Vec<u8>>)> {
        let mut state = self.state();
        if state.closed {
            return Err(ResolveError::no_response("the TLS connection closed"));
        }
        let mut id = out.id;
        let mut tries = 0;
        while state.pending.contains_key(&id) {
            tries += 1;
            if tries > 64 {
                return Err(ResolveError::no_response(
                    "no free query ID on the TLS connection",
                ));
            }
            id = rand::random();
        }
        let (tx, rx) = oneshot::channel();
        state.pending.insert(
            id,
            Pending {
                qname: out.qname.clone(),
                qtype: out.qtype,
                qclass: out.qclass,
                reply: tx,
            },
        );
        state.last_used = Instant::now();
        Ok((Waiting { conn: self, id }, rx))
    }

    async fn send(&self, query: &[u8]) -> io::Result<()> {
        let framed = crate::framed(query)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut writer = self.writer.lock().await;
        let Some(writer) = writer.as_mut() else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "closed"));
        };
        writer.write_all(&framed).await?;
        writer.flush().await
    }

    fn deliver(&self, frame: Vec<u8>, metrics: &DnsMetrics) -> Delivered {
        let Ok(msg) = DnsMessage::try_from_bytes(&frame) else {
            return Delivered::Broken;
        };
        let mut state = self.state();
        state.last_used = Instant::now();
        // RFC 7828 §3.2.2: a timeout in units of 100 ms. Zero means close
        // once nothing is pending.
        if let Some(Ok(Some(data))) = msg
            .edns
            .as_ref()
            .map(|e| e.option(crate::EDNS_OPTION_TCP_KEEPALIVE))
        {
            if let Ok(units) = <[u8; 2]>::try_from(data.as_slice()) {
                state.idle = Duration::from_millis(u64::from(u16::from_be_bytes(units)) * 100);
            }
        }
        let Some(pending) = state.pending.get(&msg.id) else {
            metrics
                .upstream_tls_unmatched
                .fetch_add(1, Ordering::Relaxed);
            return Delivered::Unmatched;
        };
        let asked = msg.queries.first().is_some_and(|q| {
            q.qname == pending.qname && q.qtype == pending.qtype && q.qclass == pending.qclass
        });
        if !asked {
            return Delivered::Broken;
        }
        if let Some(pending) = state.pending.remove(&msg.id) {
            let _ = pending.reply.send(frame);
        }
        Delivered::Answered
    }

    /// When to look again at whether the connection has idled out.
    fn idle_check(&self) -> Option<Instant> {
        let mut state = self.state();
        let now = Instant::now();
        if !state.pending.is_empty() {
            state.last_used = now;
        }
        let at = state.last_used + state.idle;
        (at > now).then_some(at)
    }

    /// Closed for good: every waiter told, the writer shut.
    async fn close(&self) {
        {
            let mut state = self.state();
            state.closed = true;
            // Dropping the senders is the waiters' "closed".
            state.pending.clear();
        }
        if let Some(mut writer) = self.writer.lock().await.take() {
            let _ = writer.shutdown().await;
        }
    }
}

async fn read_frame(
    mut reader: ReadHalf<TlsStream<TcpStream>>,
) -> (ReadHalf<TlsStream<TcpStream>>, io::Result<Vec<u8>>) {
    let mut len = [0u8; 2];
    if let Err(e) = reader.read_exact(&mut len).await {
        return (reader, Err(e));
    }
    let mut frame = vec![0; u16::from_be_bytes(len) as usize];
    let read = reader.read_exact(&mut frame).await.map(|_| frame);
    (reader, read)
}

/// Read until the server closes, the stream breaks, the connection idles out
/// or is told to close. The read is one future kept across loop turns:
/// `read_exact` is not cancel-safe (`CLAUDE.md` §9), and the other arms only
/// ever end the connection.
async fn read_loop(
    conn: Arc<Connection>,
    reader: ReadHalf<TlsStream<TcpStream>>,
    metrics: DnsMetrics,
    addr: SocketAddr,
) {
    let mut next = Box::pin(read_frame(reader));
    loop {
        let Some(idle_at) = conn.idle_check() else {
            tracing::debug!("closing the idle TLS connection to {addr}");
            break;
        };
        tokio::select! {
            (reader, frame) = &mut next => {
                let Ok(frame) = frame else { break };
                match conn.deliver(frame, &metrics) {
                    Delivered::Answered => {}
                    Delivered::Unmatched => {
                        tracing::debug!("{addr} over TLS sent a reply to no pending query");
                    }
                    Delivered::Broken => {
                        tracing::warn!(
                            "{addr} over TLS answered a query with another question; \
                             closing the connection"
                        );
                        break;
                    }
                }
                next.set(read_frame(reader));
            }
            () = tokio::time::sleep_until(idle_at.into()) => {}
            () = conn.closing.notified() => break,
        }
    }
    conn.close().await;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::server::TlsStream as ServerStream;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::{Class, ParsedRecord, RecordData, ResourceRecord, Ttl};

    /// A CA, and a leaf for `dot.test` it signed.
    struct Pki {
        ca_pem: String,
        leaf: CertificateDer<'static>,
        key: Vec<u8>,
    }

    fn pki() -> Pki {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("a CA key");
        let ca = ca_params.self_signed(&ca_key).expect("the CA");
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().expect("a leaf key");
        let leaf = CertificateParams::new(vec!["dot.test".to_string()])
            .expect("params")
            .signed_by(&leaf_key, &issuer)
            .expect("the leaf");
        Pki {
            ca_pem: ca.pem(),
            leaf: leaf.der().clone(),
            key: leaf_key.serialize_der(),
        }
    }

    fn trust(pki: &Pki) -> TlsClientTrust {
        let path = std::env::temp_dir().join(format!(
            "rdns-dot-ca-{}-{}.pem",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::write(&path, &pki.ca_pem).expect("write the CA");
        let trust = TlsClientTrust::from_ca_file(&path, None).expect("anchors");
        let _ = std::fs::remove_file(&path);
        trust
    }

    fn acceptor(pki: &Pki, versions: &[&'static rustls::SupportedProtocolVersion]) -> TlsAcceptor {
        let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
            .with_no_client_auth()
            .with_single_cert(
                vec![pki.leaf.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.clone())),
            )
            .expect("a server config");
        config.alpn_protocols = vec![b"dot".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }

    /// What the test server does with the queries on one connection.
    #[derive(Clone, Copy)]
    enum Behaviour {
        /// Answer each as it arrives.
        Answer,
        /// Wait for this many, then answer them in reverse.
        Batch(usize),
        /// First send a reply with an ID nothing awaits, then answer.
        StrayFirst,
        /// Answer with another question under the query's ID.
        WrongQuestion,
        /// Answer, advertising this keepalive in units of 100 ms.
        Keepalive(u16),
    }

    struct TestServer {
        addr: SocketAddr,
        handshakes: Arc<AtomicUsize>,
        lengths: Arc<Mutex<Vec<usize>>>,
        /// Bound on the same port, to see nothing arrive in clear.
        udp: std::net::UdpSocket,
    }

    async fn serve(acceptor: TlsAcceptor, behaviour: Behaviour) -> TestServer {
        let (listener, udp) = loop {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("bound").port();
            if let Ok(udp) = std::net::UdpSocket::bind(("127.0.0.1", port)) {
                break (listener, udp);
            }
        };
        udp.set_nonblocking(true).expect("nonblocking");
        let server = TestServer {
            addr: listener.local_addr().expect("bound"),
            handshakes: Arc::new(AtomicUsize::new(0)),
            lengths: Arc::new(Mutex::new(Vec::new())),
            udp,
        };
        let (handshakes, lengths) = (server.handshakes.clone(), server.lengths.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let (handshakes, lengths) = (handshakes.clone(), lengths.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    handshakes.fetch_add(1, Ordering::SeqCst);
                    converse(tls, behaviour, lengths).await;
                });
            }
        });
        server
    }

    async fn converse(
        mut tls: ServerStream<TcpStream>,
        behaviour: Behaviour,
        lengths: Arc<Mutex<Vec<usize>>>,
    ) {
        let mut held = Vec::new();
        loop {
            let mut len = [0u8; 2];
            if tls.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut query = vec![0; u16::from_be_bytes(len) as usize];
            if tls.read_exact(&mut query).await.is_err() {
                return;
            }
            lengths.lock().unwrap().push(query.len());
            let query = DnsMessage::try_from_bytes(&query).expect("a query");
            let replies = match behaviour {
                Behaviour::Answer => vec![reply(&query, None)],
                Behaviour::Keepalive(units) => vec![reply(&query, Some(units))],
                Behaviour::StrayFirst => {
                    let mut stray = reply(&query, None);
                    stray.id = query.id.wrapping_add(1);
                    vec![stray, reply(&query, None)]
                }
                Behaviour::WrongQuestion => {
                    let mut wrong = reply(&query, None);
                    wrong.queries[0].qname = "elsewhere.test.".parse().unwrap();
                    vec![wrong]
                }
                Behaviour::Batch(n) => {
                    held.push(query);
                    if held.len() < n {
                        continue;
                    }
                    held.drain(..).rev().map(|q| reply(&q, None)).collect()
                }
            };
            for reply in replies {
                let bytes = reply.to_bytes_within(4096).expect("serialize");
                let framed = crate::framed(&bytes).expect("framed");
                if tls.write_all(&framed).await.is_err() {
                    return;
                }
            }
        }
    }

    fn reply(query: &DnsMessage, keepalive: Option<u16>) -> DnsMessage {
        let mut reply = query.clone();
        reply.response = true;
        reply.recursion_ok = true;
        reply.answers = vec![ResourceRecord {
            name: query.queries[0].qname.clone(),
            class: Class::IN,
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 53)))
                .expect("encodes"),
        }];
        reply.edns = None;
        let options: Vec<_> = keepalive
            .map(|units| crate::EdnsOption {
                code: crate::EDNS_OPTION_TCP_KEEPALIVE,
                data: units.to_be_bytes().to_vec(),
            })
            .into_iter()
            .collect();
        reply.set_edns(Edns::with_options(1232, 0, false, &options).expect("an OPT"));
        reply
    }

    fn forwarding(trust: TlsClientTrust, servers: &[(SocketAddr, &str)]) -> (Resolver, DnsMetrics) {
        let metrics = DnsMetrics::new();
        let config = ResolverConfig {
            routes: vec![Route::forward(
                Name::root(),
                servers.iter().map(|(addr, _)| *addr).collect(),
            )],
            dot: Some(DotConfig {
                trust,
                servers: servers
                    .iter()
                    .map(|(addr, name)| (*addr, AuthName::parse(name).expect("a name")))
                    .collect(),
            }),
            metrics: metrics.clone(),
            timeout_ms: 2000,
            ..Default::default()
        };
        (Resolver::new(config), metrics)
    }

    fn question(name: &str) -> QuerySection {
        QuerySection {
            qname: name.parse().expect("a name"),
            qtype: Qtype::of(Rtype::new(1)),
            qclass: QueryClass::IN,
        }
    }

    fn failures(metrics: &DnsMetrics) -> u64 {
        metrics
            .upstream_tls_handshake_failures
            .load(Ordering::Relaxed)
    }

    /// Answered over TLS, never in clear, and every query padded to a
    /// multiple of 128 (RFC 8467 §4.1(1)).
    #[tokio::test]
    async fn a_forwarded_query_goes_over_tls_and_only_tls() {
        let pki = pki();
        let server = serve(
            acceptor(&pki, &[&rustls::version::TLS13]),
            Behaviour::Answer,
        )
        .await;
        let (resolver, _) = forwarding(trust(&pki), &[(server.addr, "dot.test")]);

        for name in ["a.example.", "b.example."] {
            let answer = resolver.resolve(&question(name)).await.expect("answered");
            assert_eq!(answer.answers.len(), 1, "{name}");
        }
        assert!(
            server.udp.recv(&mut [0u8; 512]).is_err(),
            "nothing reached the UDP port"
        );
        let lengths = server.lengths.lock().unwrap().clone();
        assert_eq!(lengths.len(), 2);
        assert!(lengths.iter().all(|l| l % 128 == 0), "{lengths:?}");
        assert_eq!(
            server.handshakes.load(Ordering::SeqCst),
            1,
            "one connection"
        );
    }

    /// Wrong name, untrusted CA, TLS 1.2 only: each fails the handshake and is
    /// counted; the next server answers; with none left, EDE 22.
    #[tokio::test]
    async fn a_failed_handshake_moves_on_and_with_nothing_left_is_unreachable() {
        let pki = pki();
        let stranger = pki_stranger();
        let good = serve(
            acceptor(&pki, &[&rustls::version::TLS13]),
            Behaviour::Answer,
        )
        .await;
        let tls12 = serve(
            acceptor(&pki, &[&rustls::version::TLS12]),
            Behaviour::Answer,
        )
        .await;
        let untrusted = serve(
            acceptor(&stranger, &[&rustls::version::TLS13]),
            Behaviour::Answer,
        )
        .await;
        let misnamed = serve(
            acceptor(&pki, &[&rustls::version::TLS13]),
            Behaviour::Answer,
        )
        .await;
        let cases = [
            (misnamed.addr, "wrong.test"),
            (tls12.addr, "dot.test"),
            (untrusted.addr, "dot.test"),
        ];
        for (addr, name) in cases {
            let (resolver, metrics) =
                forwarding(trust(&pki), &[(addr, name), (good.addr, "dot.test")]);
            resolver
                .resolve(&question("a.example."))
                .await
                .expect("the next server answers");
            assert_eq!(failures(&metrics), 1, "{addr} as {name}");

            let (alone, metrics) = forwarding(trust(&pki), &[(addr, name)]);
            let err = alone
                .resolve(&question("a.example."))
                .await
                .expect_err("nothing left");
            assert_eq!(
                err.extended_error().info_code(),
                crate::InfoCode::NO_REACHABLE_AUTHORITY,
                "{err}"
            );
            assert!(failures(&metrics) >= 1);
        }
    }

    fn pki_stranger() -> Pki {
        pki()
    }

    /// Twenty concurrent queries, one handshake, answered in reverse order.
    #[tokio::test]
    async fn twenty_queries_share_one_connection_and_are_matched_out_of_order() {
        let pki = pki();
        let server = serve(
            acceptor(&pki, &[&rustls::version::TLS13]),
            Behaviour::Batch(20),
        )
        .await;
        let (resolver, _) = forwarding(trust(&pki), &[(server.addr, "dot.test")]);
        let resolver = Arc::new(resolver);
        let mut asked = tokio::task::JoinSet::new();
        for i in 0..20 {
            let resolver = resolver.clone();
            asked.spawn(async move {
                let name = format!("q{i}.example.");
                let answer = resolver.resolve(&question(&name)).await.expect("answered");
                assert_eq!(answer.answers[0].name, name.parse::<Name>().unwrap());
            });
        }
        while let Some(done) = asked.join_next().await {
            done.expect("each query answered with its own name");
        }
        assert_eq!(server.handshakes.load(Ordering::SeqCst), 1);
    }

    /// A stray ID is dropped and the connection kept; a wrong question
    /// closes it and the next query reconnects.
    #[tokio::test]
    async fn a_stray_reply_is_dropped_and_a_wrong_question_closes_the_connection() {
        let pki = pki();
        let stray = serve(
            acceptor(&pki, &[&rustls::version::TLS13]),
            Behaviour::StrayFirst,
        )
        .await;
        let (resolver, metrics) = forwarding(trust(&pki), &[(stray.addr, "dot.test")]);
        for name in ["a.example.", "b.example."] {
            resolver.resolve(&question(name)).await.expect("answered");
        }
        assert_eq!(stray.handshakes.load(Ordering::SeqCst), 1, "kept");
        assert_eq!(metrics.upstream_tls_unmatched.load(Ordering::Relaxed), 2);

        let wrong = serve(
            acceptor(&pki, &[&rustls::version::TLS13]),
            Behaviour::WrongQuestion,
        )
        .await;
        let (resolver, _) = forwarding(trust(&pki), &[(wrong.addr, "dot.test")]);
        for name in ["a.example.", "b.example."] {
            resolver
                .resolve(&question(name))
                .await
                .expect_err("never answered");
        }
        assert_eq!(
            wrong.handshakes.load(Ordering::SeqCst),
            2,
            "closed after the first, reconnected for the second"
        );
    }

    /// The server's keepalive is honoured: 200 ms, then a new connection.
    #[tokio::test]
    async fn an_idle_connection_closes_at_the_servers_keepalive() {
        let pki = pki();
        let server = serve(
            acceptor(&pki, &[&rustls::version::TLS13]),
            Behaviour::Keepalive(2),
        )
        .await;
        let (resolver, _) = forwarding(trust(&pki), &[(server.addr, "dot.test")]);
        resolver
            .resolve(&question("a.example."))
            .await
            .expect("answered");
        resolver
            .resolve(&question("b.example."))
            .await
            .expect("answered");
        assert_eq!(server.handshakes.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(500)).await;
        resolver
            .resolve(&question("c.example."))
            .await
            .expect("answered");
        assert_eq!(server.handshakes.load(Ordering::SeqCst), 2, "reconnected");
    }
}
