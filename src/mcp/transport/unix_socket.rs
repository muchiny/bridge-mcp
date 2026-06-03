//! Unix Domain Socket Transport
//!
//! Multi-session transport backed by a `tokio::net::UnixListener`. Each
//! `accept()` call returns the next client connection as a fresh
//! [`Session`]. This is the transport used by the daemon mode
//! (`bridge-mcp daemon start`) to serve many clients on a shared
//! socket without paying SSH pool cold-start costs per request.
//!
//! The transport owns a `CancellationToken` that callers can trigger
//! (via [`UnixSocketTransport::shutdown_token`]) to break out of the
//! accept loop — used by `run_daemon` to react to SIGINT.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, unix::OwnedWriteHalf};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use super::{Session, SessionReader, SessionWriter, Transport};
use crate::mcp::protocol::{IncomingMessage, WriterMessage};
use crate::mcp::server::McpServer;

/// Multi-session Unix socket transport.
pub struct UnixSocketTransport {
    listener: UnixListener,
    socket_path: PathBuf,
    shutdown: CancellationToken,
}

impl UnixSocketTransport {
    /// Bind a new listener at `path`.
    ///
    /// Removes any pre-existing file at that path (e.g. stale socket
    /// from a crashed daemon) before binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be removed, the bind
    /// fails, or the parent directory does not exist.
    pub fn bind(path: &Path) -> crate::error::Result<Self> {
        // Remove any stale file (but tolerate NotFound).
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(crate::error::BridgeError::Io(e)),
        }

        let listener = UnixListener::bind(path).map_err(crate::error::BridgeError::Io)?;
        Ok(Self {
            listener,
            socket_path: path.to_path_buf(),
            shutdown: CancellationToken::new(),
        })
    }

    /// Return a handle to trigger graceful shutdown.
    ///
    /// Calling `cancel()` on the returned token makes the next
    /// [`Transport::accept`] call return `None`, letting the serve loop
    /// exit cleanly.
    #[must_use]
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }
}

#[async_trait]
impl Transport for UnixSocketTransport {
    async fn accept(&mut self) -> Option<Session> {
        loop {
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => {
                    return None;
                }
                accept = self.listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            let (reader, writer) = stream.into_split();
                            let session_reader: Box<dyn SessionReader> =
                                Box::new(UnixSessionReader::new(reader));
                            let session_writer: Box<dyn SessionWriter> =
                                Box::new(UnixSessionWriter::new(writer));
                            return Some(Session {
                                reader: session_reader,
                                writer: session_writer,
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "UnixListener accept failed");
                            // Brief backoff so a persistent error doesn't busy-spin,
                            // then fall through to the next loop iteration.
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    }

    async fn shutdown(&self) {
        self.shutdown.cancel();
        // Best-effort cleanup: remove the socket file. Ignore errors —
        // we're exiting.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Reader half of a Unix socket session: line-delimited JSON-RPC.
pub struct UnixSessionReader {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
}

impl UnixSessionReader {
    fn new(reader: tokio::net::unix::OwnedReadHalf) -> Self {
        Self {
            reader: BufReader::new(reader),
        }
    }
}

#[async_trait]
impl SessionReader for UnixSessionReader {
    async fn recv(&mut self) -> Option<std::result::Result<IncomingMessage, String>> {
        loop {
            let mut line = String::new();

            let bytes_read = match self.reader.read_line(&mut line).await {
                Ok(n) => n,
                Err(e) => {
                    debug!(error = %e, "Unix session read failed");
                    return None;
                }
            };
            if bytes_read == 0 {
                return None; // client closed the write side
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            debug!(request = %trimmed, "Unix session received message");

            return match McpServer::parse_incoming(trimmed) {
                Ok(msg) => Some(Ok(msg)),
                Err(e) => {
                    warn!(error = %e, line = %trimmed, "Unix session parse failed");
                    Some(Err(e.to_string()))
                }
            };
        }
    }
}

/// Writer half of a Unix socket session.
pub struct UnixSessionWriter {
    writer: OwnedWriteHalf,
}

impl UnixSessionWriter {
    fn new(writer: OwnedWriteHalf) -> Self {
        Self { writer }
    }
}

#[async_trait]
impl SessionWriter for UnixSessionWriter {
    async fn send(&mut self, msg: WriterMessage) -> crate::error::Result<()> {
        let json_str = match &msg {
            WriterMessage::Response(r) => serde_json::to_string(r),
            WriterMessage::Notification(n) => serde_json::to_string(n),
            WriterMessage::Request(r) => serde_json::to_string(&r),
            WriterMessage::BatchResponse(responses) => serde_json::to_string(responses),
        };
        let Ok(json_str) = json_str else {
            error!("Failed to serialize Unix session message");
            return Ok(());
        };

        debug!(message = %json_str, "Unix session sending message");

        self.writer
            .write_all(json_str.as_bytes())
            .await
            .map_err(crate::error::BridgeError::Io)?;
        self.writer
            .write_all(b"\n")
            .await
            .map_err(crate::error::BridgeError::Io)?;
        self.writer
            .flush()
            .await
            .map_err(crate::error::BridgeError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_unix_transport_bind_creates_socket_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("bind_test.sock");
        let _t = UnixSocketTransport::bind(&path).unwrap();
        assert!(
            path.exists(),
            "UnixSocketTransport::bind must create the socket file"
        );
    }

    #[tokio::test]
    async fn test_unix_transport_shutdown_token_ends_accept() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("shutdown_test.sock");
        let mut t = UnixSocketTransport::bind(&path).unwrap();
        let token = t.shutdown_token();

        // Cancel the token immediately: next accept must return None.
        token.cancel();
        let session = t.accept().await;
        assert!(session.is_none());
    }

    #[tokio::test]
    async fn test_unix_transport_bind_removes_stale_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("stale.sock");
        // Write a junk file at the socket path to simulate a stale file.
        std::fs::write(&path, b"not a socket").unwrap();
        assert!(path.exists());

        // bind() should remove the stale file and succeed.
        let _t = UnixSocketTransport::bind(&path).unwrap();
        assert!(path.exists(), "new socket file should exist");
    }

    #[tokio::test]
    async fn test_unix_transport_accept_produces_session() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("accept.sock");
        let mut t = UnixSocketTransport::bind(&path).unwrap();

        // Connect a client in a background task so accept() can return.
        let client_path = path.clone();
        let client_task = tokio::spawn(async move {
            let _stream = tokio::net::UnixStream::connect(&client_path).await.unwrap();
        });

        let session = t.accept().await;
        assert!(
            session.is_some(),
            "accept must yield a Session for a new client connection"
        );
        let _ = client_task.await;
    }
}
