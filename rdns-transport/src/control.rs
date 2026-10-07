//! The control channel's transport, shared by both daemons: bind, accept, one
//! command per connection, a read timeout. Each daemon supplies only its
//! command table, as [`Commands`] (`TODO.md` #178). The line protocol is
//! [`rdns::control`].
//!
//! A Unix socket, owner-only by file mode. Unix-only for now: a daemon refuses
//! `--control-socket` on Windows rather than accepting and ignoring it
//! (`TODO.md` #188 is the Windows half).

use std::future::Future;
#[cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

use rdns::control::{err, Request, MAX_REQUEST};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How long a client gets to send its command before we give up on it.
#[cfg_attr(not(unix), allow(dead_code))]
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A daemon's answer to a control command: the reply text, already framed by
/// [`rdns::control::ok`] or [`err`].
pub trait Commands: Send + Sync + 'static {
    fn run(&self, request: Request) -> impl Future<Output = String> + Send;
}

#[cfg(unix)]
pub use unix::{bind, serve};

#[cfg(unix)]
mod unix {
    use std::path::{Path, PathBuf};

    use anyhow::{anyhow, Context, Result};
    use rdns::persist;
    use rdns::shutdown::{Busy, Stop};
    use tokio::net::UnixListener;

    use super::*;

    /// Bind the socket, refusing rather than stealing it if a server is
    /// already there.
    ///
    /// - `connect` first: something accepting means another server holds the
    ///   path. Connection refused means a leftover from a dead process, which
    ///   must not stop a start.
    /// - Bind under a temporary name, restrict to the owner, rename over the
    ///   target: the mode is in place before the published path exists, and
    ///   the rename leaves no unlink-then-bind gap for a racing process.
    pub fn bind(path: &Path) -> Result<UnixListener> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() && !dir.is_dir() {
                return Err(anyhow!(
                    "--control-socket {}: {} is not a directory",
                    path.display(),
                    dir.display()
                ));
            }
        }
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(anyhow!(
                "--control-socket {}: another server is already listening there",
                path.display()
            ));
        }

        let temp = temp_path(path);
        // A leftover from an interrupted start of our own; the target is left
        // alone until the rename.
        let _ = std::fs::remove_file(&temp);
        let listener = UnixListener::bind(&temp)
            .with_context(|| format!("--control-socket {}", path.display()))?;
        let restricted =
            persist::restrict_to_owner(&temp).and_then(|()| std::fs::rename(&temp, path));
        if let Err(e) = restricted {
            let _ = std::fs::remove_file(&temp);
            return Err(
                anyhow::Error::from(e).context(format!("--control-socket {}", path.display()))
            );
        }
        Ok(listener)
    }

    /// `<name>.<pid>.tmp` beside the target, so two servers racing to start
    /// cannot collide on the temporary either.
    fn temp_path(path: &Path) -> PathBuf {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".{}.tmp", std::process::id()));
        path.with_file_name(name)
    }

    /// Accept control connections until told to stop.
    ///
    /// The socket file is removed on the way out: a leftover makes `rdnsctl`
    /// say "connection refused" where "no such file" is the truth.
    pub async fn serve<C: Commands>(
        listener: UnixListener,
        path: PathBuf,
        commands: Arc<C>,
        stop: Stop,
        busy: Busy,
    ) -> Result<(), std::io::Error> {
        let result = accept_loop(listener, &commands, stop, busy).await;
        let _ = std::fs::remove_file(&path);
        result
    }

    async fn accept_loop<C: Commands>(
        listener: UnixListener,
        commands: &Arc<C>,
        stop: Stop,
        busy: Busy,
    ) -> Result<(), std::io::Error> {
        loop {
            // `accept` is cancel-safe, so losing this race drops nothing.
            let (stream, _) = tokio::select! {
                accepted = listener.accept() => accepted?,
                _ = stop.wait() => return Ok(()),
            };
            let commands = commands.clone();
            // A command in flight holds the drain: a half-written `dump`
            // cannot be told from a complete one.
            let busy = busy.clone();
            tokio::spawn(async move {
                let _busy = busy;
                if let Err(e) = converse(stream, &*commands).await {
                    // DEBUG: a client hanging up mid-write is not actionable,
                    // and this socket is reachable only by the trusted.
                    tracing::debug!("control connection: {e}");
                }
            });
        }
    }
}

/// One connection: read a command, run it, write the reply, close.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) async fn converse<S, C>(mut stream: S, commands: &C) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: Commands,
{
    let mut buf = Vec::with_capacity(256);
    let line = loop {
        if let Some(at) = buf.iter().position(|b| *b == b'\n') {
            break String::from_utf8_lossy(&buf[..at]).into_owned();
        }
        if buf.len() >= MAX_REQUEST {
            return write_all(&mut stream, &err("command too long")).await;
        }
        let mut chunk = [0u8; 256];
        match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut chunk)).await {
            // A client that closed without a newline still gets its command
            // run: `printf status | socat ...` sends no trailing newline.
            Ok(Ok(0)) => break String::from_utf8_lossy(&buf).into_owned(),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e),
            Err(_) => return write_all(&mut stream, &err("timed out waiting for a command")).await,
        }
    };

    let reply = commands.run(Request::parse(&line)).await;
    write_all(&mut stream, &reply).await
}

#[cfg_attr(not(unix), allow(dead_code))]
async fn write_all<S: AsyncWrite + Unpin>(stream: &mut S, text: &str) -> std::io::Result<()> {
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await
}
