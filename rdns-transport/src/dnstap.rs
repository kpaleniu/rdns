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
use rdns::shutdown::Lifecycle;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// `Dnstap.identity`: this host, as the environment names it.
///
/// `HOSTNAME` then `COMPUTERNAME`, and empty if neither is set — which the
/// encoder omits rather than writing as an empty string. `std` has no portable
/// way to ask the OS and a crate for one field of one optional output is not a
/// dependency this earns (`CLAUDE.md` §14). An operator who needs a particular
/// identity sets the variable, which is where a service manager already puts it.
pub fn hostname() -> Vec<u8> {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .map(String::into_bytes)
        .unwrap_or_default()
}

/// How many encoded payloads may be waiting for the writer.
///
/// Enough to ride out a collector's GC pause or a file's `fsync`, not enough to
/// hold a flood: at ~100 octets a payload this is a few megabytes at worst, and
/// a sink that stays behind is a dropped-payload count rather than growing
/// memory.
const QUEUE_DEPTH: usize = 8192;

/// Where the stream goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
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
pub struct Sink {
    frames: mpsc::Sender<Vec<u8>>,
    metrics: DnsMetrics,
    identity: Arc<Vec<u8>>,
    version: Arc<Vec<u8>>,
}

impl Sink {
    /// `Dnstap.identity`, usually the host name, and `Dnstap.version`.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    pub fn version(&self) -> &[u8] {
        &self.version
    }

    /// Queue one already-encoded payload, or count it as dropped.
    ///
    /// `try_send`, never `send`: this is called from the answer path, and an
    /// `.await` here would put a collector that stopped reading in front of
    /// every query.
    pub fn send(&self, payload: Vec<u8>) {
        match self.frames.try_send(payload) {
            Ok(()) => self.metrics.count(&self.metrics.dnstap_frames),
            // Full, or the writer task is gone. Both are "this payload is not
            // going anywhere", and both are the counter's business.
            Err(_) => self.metrics.count(&self.metrics.dnstap_dropped),
        }
    }

    /// Encode `entry` and queue it. Nothing is encoded when the queue is
    /// already full, which is the cheap half of the drop.
    pub fn record(&self, entry: &dnstap::Entry<'_>) {
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
    /// Opened here so a bad target fails at startup with a message, not as a
    /// silently absent stream (`CLAUDE.md` §4). Appended to, never rotated or
    /// reopened: `--dnstap-max-bytes` is the bound. The pump holds `Busy` until
    /// the stream is closed, so the drain waits for the capture's tail.
    pub async fn spawn(
        target: &Target,
        max_bytes: u64,
        identity: Vec<u8>,
        version: Vec<u8>,
        metrics: DnsMetrics,
        lifecycle: Lifecycle,
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
                tokio::spawn(pump(stream, queue, true, u64::MAX, metrics, lifecycle));
            }
            Target::File(path) => {
                let file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await
                    .with_context(|| format!("opening the dnstap file {}", path.display()))?;
                tokio::spawn(pump(file, queue, false, max_bytes, metrics, lifecycle));
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
    lifecycle: Lifecycle,
) where
    W: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let Lifecycle { stop, busy: _busy } = lifecycle;
    if let Err(e) = handshake(&mut writer, bidirectional).await {
        // ERROR: the stream never opened, so every payload after this is a
        // drop, and the counter alone would not say why.
        tracing::error!("dnstap stream did not open: {e}");
        return;
    }

    let mut cap = Cap {
        max_bytes,
        written: 0,
        capped: false,
    };
    loop {
        let frame = tokio::select! {
            frame = queue.recv() => frame,
            _ = stop.wait() => break,
        };
        let Some(frame) = frame else { break };
        if put(&mut writer, &mut cap, &metrics, &frame).await.is_err() {
            return;
        }
    }

    // Queued before the stop, which `Sink::send` counted as sent; after it,
    // `send` counts a payload as dropped.
    while let Ok(frame) = queue.try_recv() {
        if put(&mut writer, &mut cap, &metrics, &frame).await.is_err() {
            return;
        }
    }

    // STOP marks a clean end, so `dnstap -r` prints a summary rather than
    // reporting a truncated file.
    if let Err(e) = writer.write_all(&dnstap::stop_frame()).await {
        tracing::error!("dnstap STOP not written: {e}");
        return;
    }
    if let Err(e) = writer.flush().await {
        tracing::error!("dnstap stream not flushed: {e}");
        return;
    }
    // The collector answers STOP with FINISH, as `fstrm_capture` does; fstrm's
    // writer waits for it before closing. Bounded by the drain budget.
    if bidirectional {
        if let Err(e) = wait_for(&mut writer, dnstap::ControlFrame::Finish, "FINISH").await {
            tracing::warn!("dnstap collector did not finish the stream: {e}");
        }
    }
}

/// Write one frame if the cap admits it. `Err` means the stream is closed,
/// and has been logged.
async fn put<W>(
    writer: &mut W,
    cap: &mut Cap,
    metrics: &DnsMetrics,
    frame: &[u8],
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if !cap.admits(frame.len(), metrics) {
        return Ok(());
    }
    writer.write_all(frame).await.inspect_err(|e| {
        tracing::error!("dnstap write failed, closing the stream: {e}");
    })
}

/// `--dnstap-max-bytes`: octets written so far, against the limit.
struct Cap {
    max_bytes: u64,
    written: u64,
    capped: bool,
}

impl Cap {
    /// Whether a frame of `len` octets may be written; counted as dropped if not.
    fn admits(&mut self, len: usize, metrics: &DnsMetrics) -> bool {
        let after = self.written.saturating_add(len as u64);
        if self.max_bytes != 0 && after > self.max_bytes {
            if !self.capped {
                // Once, not per frame: a capped sink would otherwise log at the
                // query rate, which is the thing this feature exists to avoid.
                tracing::warn!(
                    "dnstap file reached --dnstap-max-bytes ({}); \
                     nothing further is written and every payload is counted as dropped",
                    self.max_bytes
                );
                self.capped = true;
            }
            metrics.count(&metrics.dnstap_dropped);
            return false;
        }
        self.written = after;
        true
    }
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
        wait_for(writer, dnstap::ControlFrame::Accept, "ACCEPT").await?;
    }
    writer
        .write_all(&dnstap::start_frame())
        .await
        .context("sending START")?;
    Ok(())
}

/// Read the collector's answer to READY or to STOP.
///
/// A reply arrives in whatever pieces the network gives it, so this accumulates
/// until a whole control frame is there — `read_control_frame` says "not yet"
/// rather than failing on a short read, which is the distinction that makes the
/// loop terminate correctly.
async fn wait_for<R>(reader: &mut R, want: dnstap::ControlFrame, what: &str) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buffer = Vec::with_capacity(64);
    let mut chunk = [0u8; 64];
    loop {
        match dnstap::read_control_frame(&buffer) {
            Ok(Some((frame, _))) if frame == want => return Ok(()),
            Ok(Some((other, _))) => {
                bail!("the dnstap collector sent {other:?}, not {what}")
            }
            Ok(None) => {}
            Err(e) => bail!("the dnstap collector is not speaking Frame Streams: {e}"),
        }
        let read = reader
            .read(&mut chunk)
            .await
            .with_context(|| format!("reading the collector's {what}"))?;
        if read == 0 {
            bail!("the dnstap collector closed the connection before {what}");
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
        // A queue of one with no reader: the second payload has nowhere to go.
        // `_queue` keeps the channel open; closed is the other branch.
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

    /// What was queued before the stop is written before STOP.
    ///
    /// `Sink::send` has already counted each of these in `dnstap_frames`, so a
    /// pump that drops them on stop leaves a capture missing the last requests
    /// and a counter claiming them. Fails with a `break` on `stop.wait()`: 0 or
    /// 1 of 100 written.
    #[tokio::test]
    async fn what_is_queued_when_the_stop_begins_is_written() {
        let dir = rdns::testutil::ScratchDir::new("dnstap-stop-drains");
        let path = dir.join("capture.fstrm");
        let metrics = DnsMetrics::new();
        let shutdown = Shutdown::new();
        let sink = Sink::spawn(
            &Target::File(path.clone()),
            0,
            Vec::new(),
            Vec::new(),
            metrics.clone(),
            shutdown.lifecycle(),
        )
        .await
        .expect("the file opens");

        for _ in 0..100 {
            let mut frame = Vec::new();
            dnstap::put_data_frame(&mut frame, b"payload");
            sink.send(frame);
        }

        let written = rdns::test_util::closed_capture(shutdown, &path).await;
        let frames = written
            .windows(11)
            .filter(|w| *w == b"\x00\x00\x00\x07payload")
            .count();
        assert_eq!(frames, 100, "every queued frame, then STOP");
        assert_eq!(counter(&metrics.dnstap_frames), 100);
        assert_eq!(counter(&metrics.dnstap_dropped), 0);
    }

    /// The whole exchange against a listener that behaves like `fstrm_capture`:
    /// READY out, ACCEPT back, START out, a data frame, STOP out, FINISH back.
    /// Judged by reading the socket. Fails if the pump sends FINISH itself, or
    /// releases the drain before the collector's FINISH arrives.
    #[tokio::test]
    async fn a_tcp_collector_sees_the_handshake_the_stream_and_the_close() {
        use std::time::Duration;
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let (drained_tx, drained_rx) =
            tokio::sync::oneshot::channel::<tokio::task::JoinHandle<bool>>();
        let collector = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut seen = Vec::new();
            let mut chunk = [0u8; 512];
            // READY first.
            let read = stream.read(&mut chunk).await.expect("READY");
            seen.extend_from_slice(&chunk[..read]);
            stream
                .write_all(&dnstap::accept_frame())
                .await
                .expect("ACCEPT");
            // Everything until STOP.
            let stop = dnstap::stop_frame();
            while !seen.ends_with(&stop) {
                let read = stream.read(&mut chunk).await.expect("read");
                assert_ne!(read, 0, "closed without ending on STOP");
                seen.extend_from_slice(&chunk[..read]);
            }
            // The writer is waiting for FINISH: nothing more arrives, and the
            // drain does not end.
            let mut drain = drained_rx.await.expect("the drain");
            assert!(
                tokio::time::timeout(Duration::from_millis(300), &mut drain)
                    .await
                    .is_err(),
                "the drain ended before FINISH"
            );
            stream
                .write_all(&dnstap::finish_frame())
                .await
                .expect("FINISH");
            let read = stream.read(&mut chunk).await.expect("read");
            assert_eq!(read, 0, "closed after FINISH, nothing more sent");
            let drained = tokio::time::timeout(Duration::from_secs(5), drain)
                .await
                .expect("the drain ends after FINISH")
                .expect("no panic");
            (seen, drained)
        });

        let shutdown = Shutdown::new();
        let sink = Sink::spawn(
            &Target::Tcp(addr.to_string()),
            0,
            b"ns1.example.com".to_vec(),
            b"rdnsd".to_vec(),
            DnsMetrics::new(),
            shutdown.lifecycle(),
        )
        .await
        .expect("the collector is listening");

        let mut frame = Vec::new();
        dnstap::put_data_frame(&mut frame, b"payload");
        sink.send(frame);
        drop(sink);
        shutdown.begin();
        let drain = tokio::spawn(shutdown.drain(Duration::from_secs(10)));
        assert!(drained_tx.send(drain).is_ok(), "the collector is waiting");

        let (seen, drained) = tokio::time::timeout(Duration::from_secs(10), collector)
            .await
            .expect("the collector finishes")
            .expect("no panic");
        assert!(drained, "the pump released the drain");

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
        assert_eq!(&rest[11..], dnstap::stop_frame(), "then STOP alone");
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
            shutdown.lifecycle(),
        )
        .await
        .expect("the file opens");

        for _ in 0..5 {
            let mut frame = Vec::new();
            dnstap::put_data_frame(&mut frame, b"payload");
            sink.send(frame);
        }
        drop(sink);

        let written = rdns::test_util::closed_capture(shutdown, &path).await;
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
