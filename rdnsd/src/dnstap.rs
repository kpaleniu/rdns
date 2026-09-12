//! Where dnstap payloads go, and what happens when they cannot keep up.
//!
//! `TODO.md` #44g. The encoding is [`rdns::dnstap`], which does no I/O and knows
//! nothing about `tokio`; this is the daemon half — a target to parse, one task
//! that owns the writer, and the bounded queue between it and the answer path.
//!
//! **The queue is bounded and drops rather than blocking**, which is the whole
//! design. A query must never wait on a collector: an analytics sink that stops
//! reading would otherwise become an outage, which is the amplification of a
//! logging decision into a serving one. Dropped payloads are counted
//! (`dns_dnstap_dropped_total`) because a bound with no visible shortfall is a
//! map that is quietly a lie (`CLAUDE.md` §5, §14).
//!
//! **Two targets, and neither is a Unix socket.** `tcp:` is what a collector
//! listens on and `file:` is what `dnstap -r` reads afterwards. The usual dnstap
//! transport is a Unix socket, and it is absent here for one reason worth saying
//! out loud: `tokio::net::UnixStream` is `#[cfg(unix)]`, this tree is developed
//! on Windows, and `CLAUDE.md` §1 is the story of a cfg-gated module that did
//! not compile for months behind a green suite. `rdnsd`'s control socket already
//! carries that cost because nothing else can authenticate by file mode; a
//! dnstap sink has a portable transport available and does not need to.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use rdns::dnstap;
use rdns::metrics::DnsMetrics;
use rdns::shutdown::Stop;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// How many encoded payloads may be waiting for the writer.
///
/// Enough to ride out a collector's GC pause or a file's `fsync`, not enough to
/// hold a flood: at ~100 octets a payload this is a few megabytes at worst, and
/// a sink that stays behind is a dropped-payload count rather than growing
/// memory.
const QUEUE_DEPTH: usize = 8192;

/// Where the stream goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// A collector listening on TCP, the ordinary production shape.
    Tcp(String),
    /// A capture file, which `dnstap -r` reads. Not rotated and not reopened:
    /// see [`Sink::spawn`].
    File(PathBuf),
}

impl FromStr for Target {
    type Err = anyhow::Error;

    /// `tcp:<addr:port>` or `file:<path>`.
    ///
    /// The scheme is required rather than guessed from the shape. A bare
    /// `/var/log/dnstap` and a bare `127.0.0.1:6000` are both plausible and
    /// telling them apart by inspection is how an operator gets the other one
    /// (`CLAUDE.md` §15).
    fn from_str(spec: &str) -> Result<Target> {
        match spec.split_once(':') {
            Some(("tcp", rest)) if !rest.is_empty() => Ok(Target::Tcp(rest.to_string())),
            Some(("file", rest)) if !rest.is_empty() => Ok(Target::File(PathBuf::from(rest))),
            _ => bail!(
                "a dnstap target is `tcp:<addr:port>` or `file:<path>`, not {spec:?} \
                 — the scheme is not optional, because a path and an address are \
                 not distinguishable by looking at them"
            ),
        }
    }
}

/// The handle the answer path holds, or `None` when dnstap is off.
///
/// Cloned into every task, so it is an `Arc`-free `mpsc::Sender` plus the two
/// constant fields every payload repeats.
#[derive(Clone)]
pub(crate) struct Sink {
    frames: mpsc::Sender<Vec<u8>>,
    metrics: DnsMetrics,
    identity: Arc<Vec<u8>>,
    version: Arc<Vec<u8>>,
}

impl Sink {
    /// `Dnstap.identity`, usually the host name, and `Dnstap.version`.
    pub(crate) fn identity(&self) -> &[u8] {
        &self.identity
    }

    pub(crate) fn version(&self) -> &[u8] {
        &self.version
    }

    /// Queue one already-encoded payload, or count it as dropped.
    ///
    /// `try_send`, never `send`: this is called from the answer path, and an
    /// `.await` here would put a collector that stopped reading in front of
    /// every query.
    pub(crate) fn send(&self, payload: Vec<u8>) {
        match self.frames.try_send(payload) {
            Ok(()) => self.metrics.count(&self.metrics.dnstap_frames),
            // Full, or the writer task is gone. Both are "this payload is not
            // going anywhere", and both are the counter's business.
            Err(_) => self.metrics.count(&self.metrics.dnstap_dropped),
        }
    }

    /// Encode `entry` and queue it. Nothing is encoded when the queue is
    /// already full, which is the cheap half of the drop.
    pub(crate) fn record(&self, entry: &dnstap::Entry<'_>) {
        if self.frames.capacity() == 0 {
            self.metrics.count(&self.metrics.dnstap_dropped);
            return;
        }
        let mut frame = Vec::new();
        dnstap::put_data_frame(&mut frame, &entry.encode());
        self.send(frame);
    }

    /// Open `target`, hand back the sink, and spawn the task that owns the
    /// writer.
    ///
    /// Opened here rather than in the task so that a bad target — an
    /// unreachable collector, an unwritable path — fails at startup with a
    /// message, in the order the rest of `main` fails in. A sink that reported
    /// its own misconfiguration asynchronously would leave the server up and
    /// the stream silently absent, which is §4's shape exactly.
    ///
    /// The file is opened once and appended to. It is not rotated and not
    /// reopened on SIGHUP: a capture is a capture, and a rotation policy with
    /// no way to say "and then what" is a disk-filling knob with a doc comment
    /// in front of it. `--dnstap-max-bytes` is the bound instead.
    pub(crate) async fn spawn(
        target: &Target,
        max_bytes: u64,
        identity: Vec<u8>,
        version: Vec<u8>,
        metrics: DnsMetrics,
        stop: Stop,
    ) -> Result<Sink> {
        let (frames, queue) = mpsc::channel(QUEUE_DEPTH);
        let sink = Sink {
            frames,
            metrics: metrics.clone(),
            identity: Arc::new(identity),
            version: Arc::new(version),
        };
        match target {
            Target::Tcp(addr) => {
                let stream = tokio::net::TcpStream::connect(addr)
                    .await
                    .with_context(|| format!("connecting to the dnstap collector at {addr}"))?;
                tokio::spawn(pump(stream, queue, true, u64::MAX, metrics, stop));
            }
            Target::File(path) => {
                let file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await
                    .with_context(|| format!("opening the dnstap file {}", path.display()))?;
                tokio::spawn(pump(file, queue, false, max_bytes, metrics, stop));
            }
        }
        Ok(sink)
    }
}

/// Own the writer for the life of the process: handshake, drain, close.
///
/// `bidirectional` is the difference between the two targets, and it is a
/// protocol difference rather than a preference. A collector on a socket speaks
/// the READY/ACCEPT exchange before START; a file takes START directly, because
/// there is nobody to accept.
async fn pump<W>(
    mut writer: W,
    mut queue: mpsc::Receiver<Vec<u8>>,
    bidirectional: bool,
    max_bytes: u64,
    metrics: DnsMetrics,
    stop: Stop,
) where
    W: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static,
{
    if let Err(e) = handshake(&mut writer, bidirectional).await {
        // ERROR: the stream never opened, so every payload after this is a
        // drop, and the counter alone would not say why.
        tracing::error!("dnstap stream did not open: {e}");
        return;
    }

    let mut written: u64 = 0;
    let mut capped = false;
    loop {
        let frame = tokio::select! {
            frame = queue.recv() => frame,
            _ = stop.wait() => break,
        };
        let Some(frame) = frame else { break };

        if max_bytes != 0 && written.saturating_add(frame.len() as u64) > max_bytes {
            if !capped {
                // Once, not per frame: a capped sink would otherwise log at the
                // query rate, which is the thing this feature exists to avoid.
                tracing::warn!(
                    "dnstap file reached --dnstap-max-bytes ({max_bytes}); \
                     nothing further is written and every payload is counted as dropped"
                );
                capped = true;
            }
            metrics.count(&metrics.dnstap_dropped);
            continue;
        }
        if let Err(e) = writer.write_all(&frame).await {
            tracing::error!("dnstap write failed, closing the stream: {e}");
            return;
        }
        written = written.saturating_add(frame.len() as u64);
    }

    // STOP says the stream ended rather than the reader losing its peer, which
    // is the difference between `dnstap -r` printing a summary and reporting a
    // truncated file.
    if writer.write_all(&dnstap::stop_frame()).await.is_ok() && bidirectional {
        let _ = writer.write_all(&dnstap::finish_frame()).await;
    }
    let _ = writer.flush().await;
}

/// READY/ACCEPT/START for a socket, START alone for a file.
async fn handshake<W>(writer: &mut W, bidirectional: bool) -> Result<()>
where
    W: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin,
{
    if bidirectional {
        writer
            .write_all(&dnstap::ready_frame())
            .await
            .context("sending READY")?;
        wait_for_accept(writer).await?;
    }
    writer
        .write_all(&dnstap::start_frame())
        .await
        .context("sending START")?;
    Ok(())
}

/// Read the collector's answer to READY.
///
/// A reply arrives in whatever pieces the network gives it, so this accumulates
/// until a whole control frame is there — `read_control_frame` says "not yet"
/// rather than failing on a short read, which is the distinction that makes the
/// loop terminate correctly.
async fn wait_for_accept<R>(reader: &mut R) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buffer = Vec::with_capacity(64);
    let mut chunk = [0u8; 64];
    loop {
        match dnstap::read_control_frame(&buffer) {
            Ok(Some((dnstap::ControlFrame::Accept, _))) => return Ok(()),
            Ok(Some((other, _))) => {
                bail!("the dnstap collector answered READY with {other:?}, not ACCEPT")
            }
            Ok(None) => {}
            Err(e) => bail!("the dnstap collector is not speaking Frame Streams: {e}"),
        }
        let read = reader
            .read(&mut chunk)
            .await
            .context("reading the collector's ACCEPT")?;
        if read == 0 {
            bail!("the dnstap collector closed the connection before accepting");
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdns::shutdown::Shutdown;

    #[test]
    fn a_target_needs_its_scheme_spelled_out() {
        assert_eq!(
            "tcp:127.0.0.1:6000".parse::<Target>().expect("parses"),
            Target::Tcp("127.0.0.1:6000".to_string())
        );
        assert_eq!(
            "file:/var/log/dnstap.fstrm"
                .parse::<Target>()
                .expect("parses"),
            Target::File(PathBuf::from("/var/log/dnstap.fstrm"))
        );
        // A path and an address are both plausible bare, which is the reason
        // the scheme is required rather than sniffed.
        for bad in [
            "/var/log/dnstap.fstrm",
            "127.0.0.1:6000",
            "unix:/run/d.sock",
            "tcp:",
            "",
        ] {
            let err = bad.parse::<Target>().expect_err("no scheme, no guess");
            assert!(err.to_string().contains("dnstap target is"), "{bad}: {err}");
        }
    }

    /// A collector that stops reading must not stop the server. The queue fills,
    /// `try_send` fails, and the payload is counted rather than awaited.
    #[tokio::test]
    async fn a_sink_that_cannot_keep_up_drops_and_counts_rather_than_blocking() {
        let metrics = DnsMetrics::new();
        // A queue of one, and nothing reading it: the second payload has
        // nowhere to go. The receiver is held so the channel stays open — a
        // closed one would be the other half of the same branch.
        let (frames, _queue) = mpsc::channel(1);
        let sink = Sink {
            frames,
            metrics: metrics.clone(),
            identity: Arc::new(b"ns1.example.com".to_vec()),
            version: Arc::new(b"rdnsd".to_vec()),
        };

        sink.send(vec![1, 2, 3]);
        assert_eq!(counter(&metrics.dnstap_frames), 1);
        assert_eq!(counter(&metrics.dnstap_dropped), 0);

        for _ in 0..10 {
            sink.send(vec![4, 5, 6]);
        }
        assert_eq!(counter(&metrics.dnstap_frames), 1, "one got through");
        assert_eq!(counter(&metrics.dnstap_dropped), 10, "and ten did not");
    }

    fn counter(c: &std::sync::atomic::AtomicU64) -> u64 {
        c.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The whole exchange against a listener that behaves like a collector:
    /// READY out, ACCEPT back, START out, a data frame, then STOP and FINISH on
    /// shutdown. Judged by reading the socket, not by inspecting the writer.
    #[tokio::test]
    async fn a_tcp_collector_sees_the_handshake_the_stream_and_the_close() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let collector = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut seen = Vec::new();
            let mut chunk = [0u8; 512];
            // READY first.
            let read = stream.read(&mut chunk).await.expect("READY");
            seen.extend_from_slice(&chunk[..read]);
            // ACCEPT back, carrying the content type as a real collector does.
            let mut accept = 0u32.to_be_bytes().to_vec();
            let mut body = 1u32.to_be_bytes().to_vec();
            body.extend_from_slice(&1u32.to_be_bytes());
            body.extend_from_slice(&(dnstap::CONTENT_TYPE.len() as u32).to_be_bytes());
            body.extend_from_slice(dnstap::CONTENT_TYPE);
            accept.extend_from_slice(&(body.len() as u32).to_be_bytes());
            accept.extend_from_slice(&body);
            stream.write_all(&accept).await.expect("ACCEPT");
            // And everything until the writer closes.
            loop {
                let read = stream.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(&chunk[..read]);
            }
            seen
        });

        let shutdown = Shutdown::new();
        let sink = Sink::spawn(
            &Target::Tcp(addr.to_string()),
            0,
            b"ns1.example.com".to_vec(),
            b"rdnsd".to_vec(),
            DnsMetrics::new(),
            shutdown.stop_handle(),
        )
        .await
        .expect("the collector is listening");

        let mut frame = Vec::new();
        dnstap::put_data_frame(&mut frame, b"payload");
        sink.send(frame);
        // Give the writer task the frame before asking it to stop; the drain is
        // the queue emptying, and `begin` races the send otherwise.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown.begin();
        drop(sink);

        let seen = tokio::time::timeout(std::time::Duration::from_secs(5), collector)
            .await
            .expect("the collector finishes")
            .expect("no panic");

        let ready = dnstap::ready_frame();
        assert_eq!(&seen[..ready.len()], &ready[..], "READY opens it");
        let rest = &seen[ready.len()..];
        let start = dnstap::start_frame();
        assert_eq!(&rest[..start.len()], &start[..], "then START");
        let rest = &rest[start.len()..];
        assert_eq!(
            &rest[..11],
            b"\x00\x00\x00\x07payload",
            "then the data frame"
        );
        let rest = &rest[11..];
        assert_eq!(
            rest,
            [dnstap::stop_frame(), dnstap::finish_frame()].concat()
        );
    }

    /// A file takes START directly — there is nobody to ACCEPT — and the cap
    /// stops the writing rather than the server.
    #[tokio::test]
    async fn a_file_target_is_capped_rather_than_allowed_to_fill_the_disk() {
        let dir = std::env::temp_dir().join(format!(
            "rdnsd-dnstap-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("capture.fstrm");

        let metrics = DnsMetrics::new();
        let shutdown = Shutdown::new();
        // Room for one 11-octet frame and not two.
        let sink = Sink::spawn(
            &Target::File(path.clone()),
            15,
            Vec::new(),
            Vec::new(),
            metrics.clone(),
            shutdown.stop_handle(),
        )
        .await
        .expect("the file opens");

        for _ in 0..5 {
            let mut frame = Vec::new();
            dnstap::put_data_frame(&mut frame, b"payload");
            sink.send(frame);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown.begin();
        drop(sink);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let written = std::fs::read(&path).expect("the capture file");
        let start = dnstap::start_frame();
        assert_eq!(&written[..start.len()], &start[..], "START, and no READY");
        assert_eq!(
            &written[start.len()..start.len() + 11],
            b"\x00\x00\x00\x07payload",
            "one frame fits under the cap"
        );
        assert_eq!(counter(&metrics.dnstap_dropped), 4, "and four do not");

        std::fs::remove_dir_all(&dir).ok();
    }
}
