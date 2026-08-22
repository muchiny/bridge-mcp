//! MCP Transport Layer
//!
//! Abstracts the transport mechanism behind a common session-based trait.
//!
//! The [`Transport`] trait is a **listener abstraction**: each call to
//! [`Transport::accept`] returns the next client session. Implementations
//! can be:
//!
//! - **Single-session** (e.g. [`stdio::StdioTransport`]): the first
//!   `accept()` returns a `Session` bound to stdin/stdout; subsequent
//!   calls return `None`, ending the accept loop.
//! - **Multi-session** (e.g. [`unix_socket::UnixSocketTransport`]): each
//!   `accept()` returns a fresh session corresponding to one client
//!   connection on the Unix socket.
//!
//! Each [`Session`] exposes a `reader` (incoming JSON-RPC messages) and a
//! `writer` (outgoing responses + server-initiated notifications). The
//! session reader/writer are split so the writer can be moved into a
//! dedicated background task while the main loop drives the reader — this
//! lets us use a per-session `mpsc::Sender<WriterMessage>` for
//! server-to-client notifications (elicitation, sampling, logging) that
//! are scoped to the originating connection.
//!
//! See [`crate::mcp::server::McpServer::serve`] for the generic accept
//! loop that consumes any `Transport` implementation.

pub mod stdio;
pub mod unix_socket;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "http")]
pub mod oauth;

use async_trait::async_trait;

use super::protocol::{IncomingMessage, WriterMessage};

/// Transport abstraction for MCP JSON-RPC communication.
///
/// A transport is a **session listener**: each `accept()` call yields the
/// next client session, and `None` signals the end of the accept loop
/// (client disconnected for single-session transports, shutdown
/// requested for multi-session transports).
///
/// This trait is intentionally **not** `dyn`-compatible (async functions
/// via `async_trait` are dyn-compatible, but we keep the accept/shutdown
/// methods on the concrete type for zero-cost generics in the serve
/// loop). Callers use [`crate::mcp::server::McpServer::serve`] which is
/// generic over `T: Transport`.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Accept the next client session.
    ///
    /// Returns `None` when the transport is permanently closed (EOF on
    /// stdio, or shutdown token fired on unix socket). Returns
    /// `Some(Session)` for each new client connection.
    async fn accept(&mut self) -> Option<Session>;

    /// Gracefully shut down the transport.
    ///
    /// Called after `accept()` has returned `None` to let the transport
    /// flush in-flight work, remove socket files, etc. Implementations
    /// should be idempotent.
    async fn shutdown(&self);
}

/// A single client session, split into reader and writer halves so they
/// can be driven independently.
///
/// The reader is consumed by the main accept loop's read task; the
/// writer is consumed by a per-session background task that drains the
/// notification channel and writes bytes to the underlying I/O sink.
pub struct Session {
    /// Reads incoming JSON-RPC messages from the client.
    pub reader: Box<dyn SessionReader>,
    /// Writes outgoing JSON-RPC messages to the client.
    pub writer: Box<dyn SessionWriter>,
}

/// Reads newline-delimited JSON-RPC messages from a client.
///
/// Implementations handle EOF detection, parse errors, and line framing.
#[async_trait]
pub trait SessionReader: Send {
    /// Read the next incoming message.
    ///
    /// - `None` — EOF (client disconnected, stdin closed, socket shut).
    /// - `Some(Ok(msg))` — a parsed JSON-RPC single message or batch.
    /// - `Some(Err(msg))` — the next line was not valid JSON. The serve
    ///   loop will respond with a JSON-RPC `parse_error` and keep
    ///   reading so one bad line does not kill the session.
    async fn recv(&mut self) -> Option<std::result::Result<IncomingMessage, String>>;
}

/// Writes outgoing JSON-RPC messages to a client.
///
/// Implementations are responsible for serialization and line framing.
/// A session writer is moved into its own background task — the
/// per-session `mpsc::Sender<WriterMessage>` is the only handle to it
/// after that.
#[async_trait]
pub trait SessionWriter: Send {
    /// Write one outgoing message to the client.
    ///
    /// Returns an error only on fatal I/O failure. The caller will drop
    /// the writer and log the error.
    async fn send(&mut self, msg: WriterMessage) -> crate::error::Result<()>;
}

#[cfg(test)]
mod tests {
    // Note: integration tests for concrete transports live in their own
    // modules (`stdio::tests`, `unix_socket::tests`) and exercise the
    // full accept → Session → read/write roundtrip. This module keeps
    // only the trait definitions.
}
