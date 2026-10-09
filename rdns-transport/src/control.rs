//! The control channel's transport, shared by both daemons: bind, accept, one
//! command per connection, a read timeout. Each daemon supplies only its
//! command table, as [`Commands`] (`TODO.md` #178). The line protocol is
//! [`rdns::control`].
//!
//! - Unix: a socket, owner-only by file mode.
//! - Windows: a named pipe, `\\.\pipe\NAME`. The default security descriptor
//!   gives write access only to the creator owner, administrators and
//!   LocalSystem; Everyone and anonymous get read, which cannot send a command.
//!   A custom descriptor would need tokio's `unsafe`
//!   `create_with_security_attributes_raw`.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rdns::control::{err, Request, MAX_REQUEST};
use rdns::shutdown::Busy;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How long a client gets to send its command before we give up on it.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A daemon's answer to a control command: the reply text, already framed by
/// [`rdns::control::ok`] or [`err`].
pub trait Commands: Send + Sync + 'static {
    fn run(&self, request: Request) -> impl Future<Output = String> + Send;
}

#[cfg(unix)]
pub use unix::{bind, serve, Listener};
#[cfg(windows)]
pub use windows::{bind, serve, Listener};

/// Who may send a command, for the startup banner.
pub const ACCESS: &str = if cfg!(windows) {
    "owner, administrators and SYSTEM may write"
} else {
    "mode 0600"
};

/// The first characters of every pipe name `CreateNamedPipe` accepts locally.
const PIPE_PREFIX: &str = r"\\.\pipe\";

/// Refuse a `--control-socket` this platform's transport cannot take. Called
/// above the dry run, so `--check-config` refuses it too (`CLAUDE.md` §15).
pub fn check(path: &Path) -> anyhow::Result<()> {
    if cfg!(windows) && !is_pipe_name(path) {
        anyhow::bail!(
            "--control-socket {}: on Windows this is a named pipe, {PIPE_PREFIX}NAME",
            path.display()
        );
    }
    Ok(())
}

/// `\\.\pipe\` and a name after it. The prefix is matched without case, as
/// Windows matches pipe names.
fn is_pipe_name(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    text.len() > PIPE_PREFIX.len()
        && text
            .get(..PIPE_PREFIX.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(PIPE_PREFIX))
}

#[cfg(unix)]
mod unix {
    use std::path::{Path, PathBuf};

    use anyhow::{anyhow, Context, Result};
    use rdns::persist;
    use rdns::shutdown::{Busy, Stop};
    use tokio::net::UnixListener;

    use super::*;

    pub type Listener = UnixListener;

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
            spawn_conversation(stream, commands, &busy);
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use anyhow::{anyhow, Result};
    use rdns::shutdown::{Busy, Stop};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    use super::*;

    /// The pipe's name and the instance waiting for the next client.
    #[derive(Debug)]
    pub struct Listener {
        name: OsString,
        waiting: NamedPipeServer,
    }

    /// Every instance after the first. `reject_remote_clients` is tokio's
    /// default and set anyway: a pipe is otherwise reachable over SMB.
    fn instance(name: &OsString) -> std::io::Result<NamedPipeServer> {
        ServerOptions::new()
            .reject_remote_clients(true)
            .create(name)
    }

    /// Create the pipe's first instance, refusing a name another process
    /// holds: `first_pipe_instance` is the pipe form of the socket's "refuse
    /// rather than steal". Without it a second server would add instances to
    /// the first one's pipe and the two would take turns answering.
    pub fn bind(path: &Path) -> Result<Listener> {
        check(path)?;
        let name = path.as_os_str().to_os_string();
        let waiting = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&name)
            .map_err(|e| match e.kind() {
                // ERROR_ACCESS_DENIED: `first_pipe_instance` and the name is
                // taken.
                std::io::ErrorKind::PermissionDenied => anyhow!(
                    "--control-socket {}: another server is already listening there",
                    path.display()
                ),
                _ => anyhow::Error::from(e).context(format!("--control-socket {}", path.display())),
            })?;
        Ok(Listener { name, waiting })
    }

    /// Accept control connections until told to stop. A pipe has no file to
    /// remove; it goes with its last handle.
    pub async fn serve<C: Commands>(
        listener: Listener,
        _path: PathBuf,
        commands: Arc<C>,
        stop: Stop,
        busy: Busy,
    ) -> Result<(), std::io::Error> {
        let Listener { name, mut waiting } = listener;
        loop {
            // `connect` is cancel-safe.
            let connected = tokio::select! {
                connected = waiting.connect() => connected,
                _ = stop.wait() => return Ok(()),
            };
            // The next instance before this one is handed off, so a client
            // arriving meanwhile finds one rather than ERROR_PIPE_BUSY.
            let client = std::mem::replace(&mut waiting, instance(&name)?);
            match connected {
                Ok(()) => spawn_conversation(client, &commands, &busy),
                // A client that opened and closed before the connect
                // completed (ERROR_NO_DATA) is that client's problem: the
                // instance is replaced and the loop goes on (`CLAUDE.md` §4).
                Err(e) => tracing::debug!("control pipe: {e}"),
            }
        }
    }
}

/// Run one conversation on its own task.
fn spawn_conversation<S, C>(stream: S, commands: &Arc<C>, busy: &Busy)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: Commands,
{
    let commands = commands.clone();
    // A command in flight holds the drain: a half-written `dump` cannot be
    // told from a complete one.
    let busy = busy.clone();
    tokio::spawn(async move {
        let _busy = busy;
        if let Err(e) = converse(stream, &*commands).await {
            // DEBUG: a client hanging up mid-write is not actionable, and
            // this channel is reachable only by the trusted.
            tracing::debug!("control connection: {e}");
        }
    });
}

/// One connection: read a command, run it, write the reply, close.
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
            // Nothing sent is not a command. On Windows it is what a client
            // holding only read access, which the pipe's default descriptor
            // grants Everyone, looks like; answering it `help` would be
            // answering somebody who may not write.
            Ok(Ok(0)) if buf.is_empty() => return Ok(()),
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

async fn write_all<S: AsyncWrite + Unpin>(stream: &mut S, text: &str) -> std::io::Result<()> {
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use rdns::control::ok;

    use super::*;

    /// Records each command, and answers with `size` bytes of body.
    struct Recorder {
        seen: Mutex<Vec<String>>,
        size: usize,
    }

    impl Recorder {
        fn new(size: usize) -> Arc<Recorder> {
            Arc::new(Recorder {
                seen: Mutex::new(Vec::new()),
                size,
            })
        }

        fn seen(&self) -> Vec<String> {
            self.seen.lock().expect("not poisoned").clone()
        }
    }

    impl Commands for Recorder {
        async fn run(&self, request: Request) -> String {
            self.seen
                .lock()
                .expect("not poisoned")
                .push(request.command.clone());
            ok(&"x".repeat(self.size))
        }
    }

    /// A conversation that sends nothing runs nothing, on either transport;
    /// one line without a newline still runs. The old `converse` answered the
    /// first with `help`.
    #[tokio::test]
    async fn nothing_sent_is_not_a_command() {
        let commands = Recorder::new(1);
        for sent in [&b""[..], b"status"] {
            let (mut client, server) = tokio::io::duplex(1024);
            client.write_all(sent).await.expect("send");
            client.shutdown().await.expect("half-close");
            converse(server, &*commands).await.expect("converses");
            let mut reply = String::new();
            client.read_to_string(&mut reply).await.expect("read");
            assert_eq!(reply.is_empty(), sent.is_empty(), "{sent:?}: {reply:?}");
        }
        assert_eq!(commands.seen(), ["status"]);
    }

    #[test]
    fn only_a_pipe_name_is_taken_on_windows() {
        for name in [r"\\.\pipe\rdnsd", r"\\.\PIPE\rdnsd"] {
            assert!(check(Path::new(name)).is_ok(), "{name}");
        }
        for name in [r"C:\some\path", r"\\.\pipe\", "/run/rdns/rdnsd.sock"] {
            assert_eq!(
                check(Path::new(name)).is_err(),
                cfg!(windows),
                "{name}: refused on Windows and only there"
            );
        }
    }

    #[cfg(windows)]
    fn pipe_name(test: &str) -> std::path::PathBuf {
        format!(r"\\.\pipe\rdns-test-{test}-{}", std::process::id()).into()
    }

    /// One command, a reply far larger than a pipe's buffer arriving whole
    /// after the server dropped its end, and a second command on a fresh
    /// instance.
    #[cfg(windows)]
    #[tokio::test]
    async fn the_pipe_answers_and_a_large_reply_arrives_whole() {
        use std::io::{Read, Write};

        let path = pipe_name("answers");
        let listener = bind(&path).expect("bind");
        let shutdown = rdns::shutdown::Shutdown::new();
        let commands = Recorder::new(256 * 1024);
        let server = tokio::spawn(serve(
            listener,
            path.clone(),
            commands.clone(),
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        for command in ["status", "dump"] {
            let path = path.clone();
            let reply = tokio::task::spawn_blocking(move || {
                let mut pipe = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .expect("open the pipe");
                pipe.write_all(format!("{command}\n").as_bytes())
                    .expect("send");
                let mut reply = String::new();
                pipe.read_to_string(&mut reply).expect("read");
                reply
            })
            .await
            .expect("the client joins");
            assert_eq!(reply.len(), "+OK\n".len() + 256 * 1024 + 1, "{command}");
        }
        assert_eq!(commands.seen(), ["status", "dump"]);

        shutdown.begin();
        server.await.expect("joins").expect("no io error");
    }

    /// `first_pipe_instance`: a second server is refused, not added to the
    /// first one's pipe.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_second_server_on_the_same_pipe_is_refused() {
        let path = pipe_name("second");
        let _first = bind(&path).expect("the first bind");
        let second = bind(&path).expect_err("the second bind must be refused");
        assert!(second.to_string().contains("already listening"), "{second}");
    }

    /// The default descriptor gives Everyone read access. A client holding only
    /// that cannot send, and the server must not answer it anything: the old
    /// `converse` answered an empty conversation with `help`.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_read_only_client_gets_no_command_run() {
        use std::io::Write;

        let path = pipe_name("read-only");
        let listener = bind(&path).expect("bind");
        let shutdown = rdns::shutdown::Shutdown::new();
        let commands = Recorder::new(1);
        let server = tokio::spawn(serve(
            listener,
            path.clone(),
            commands.clone(),
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let write = tokio::task::spawn_blocking({
            let path = path.clone();
            move || {
                let mut pipe = std::fs::OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .expect("read access is granted");
                pipe.write_all(
                    b"status
",
                )
            }
        })
        .await
        .expect("the client joins");
        assert!(write.is_err(), "a read-only handle cannot write");
        // Let the server see the first client go.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            commands.seen().is_empty(),
            "no command reached the table: {:?}",
            commands.seen()
        );

        shutdown.begin();
        server.await.expect("joins").expect("no io error");
    }
}
