//! Stdio Transport
//!
//! Reads JSON-RPC messages line-by-line from stdin and writes responses
//! to stdout. This is the default transport for Claude Code subprocess
//! spawning and is a **single-session** transport: the first
//! `accept()` call returns the stdin/stdout session; subsequent calls
//! return `None`.

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error};

use super::{Session, SessionReader, SessionWriter, Transport};
use crate::mcp::protocol::{JsonRpcError, JsonRpcMessage, WriterMessage};
use crate::mcp::server::McpServer;

/// Single-session stdio transport built on `tokio::io::{stdin,stdout}`.
pub struct StdioTransport {
    /// Tracks whether `accept()` has already handed out the stdin/stdout
    /// session. After the first call we must return `None` so the
    /// generic serve loop exits cleanly instead of spinning.
    accepted: bool,
}

impl StdioTransport {
    /// Create a new stdio transport.
    #[must_use]
    pub fn new() -> Self {
        Self { accepted: false }
    }
}

impl Default for StdioTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn accept(&mut self) -> Option<Session> {
        if self.accepted {
            return None;
        }
        self.accepted = true;

        let reader: Box<dyn SessionReader> = Box::new(StdioSessionReader::new());
        let writer: Box<dyn SessionWriter> = Box::new(StdioSessionWriter::new());

        Some(Session { reader, writer })
    }

    async fn shutdown(&self) {
        // Stdio does not need explicit cleanup — the OS closes the
        // handles when the process exits. The method exists for trait
        // symmetry with socket-backed transports.
    }
}

/// Reader half of the stdio session: line-delimited JSON-RPC on stdin.
pub struct StdioSessionReader {
    reader: BufReader<tokio::io::Stdin>,
}

impl StdioSessionReader {
    fn new() -> Self {
        Self {
            reader: BufReader::new(tokio::io::stdin()),
        }
    }
}

#[async_trait]
impl SessionReader for StdioSessionReader {
    async fn recv(&mut self) -> Option<std::result::Result<JsonRpcMessage, JsonRpcError>> {
        loop {
            let mut line = String::new();

            let bytes_read = self.reader.read_line(&mut line).await.ok()?;
            if bytes_read == 0 {
                return None; // EOF
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            debug!(request = %trimmed, "Received message");

            return match McpServer::parse_incoming(trimmed) {
                Ok(msg) => Some(Ok(msg)),
                Err(e) => {
                    error!(code = e.code, message = %e.message, "Rejecting message");
                    Some(Err(e))
                }
            };
        }
    }
}

/// Writer half of the stdio session: line-delimited JSON on stdout.
pub struct StdioSessionWriter {
    stdout: tokio::io::Stdout,
}

impl StdioSessionWriter {
    fn new() -> Self {
        Self {
            stdout: tokio::io::stdout(),
        }
    }
}

#[async_trait]
impl SessionWriter for StdioSessionWriter {
    async fn send(&mut self, msg: WriterMessage) -> crate::error::Result<()> {
        let json_str = match &msg {
            WriterMessage::Response(r) => serde_json::to_string(r),
            WriterMessage::Notification(n) => serde_json::to_string(n),
            WriterMessage::Request(r) => serde_json::to_string(&r),
        };
        let Ok(json_str) = json_str else {
            error!("Failed to serialize message");
            return Ok(());
        };

        debug!(message = %json_str, "Sending message");

        self.stdout.write_all(json_str.as_bytes()).await?;
        self.stdout.write_all(b"\n").await?;
        self.stdout.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdio_transport_default() {
        let _transport = StdioTransport::default();
    }

    #[test]
    fn test_stdio_transport_new() {
        let _transport = StdioTransport::new();
    }

    #[tokio::test]
    async fn test_stdio_accept_returns_none_after_first_call() {
        let mut t = StdioTransport::new();
        // First accept must return Some
        let session = t.accept().await;
        assert!(session.is_some());
        // Second accept must return None (single-session contract)
        let second = t.accept().await;
        assert!(second.is_none());
    }

    #[test]
    fn test_parse_incoming_single_request() {
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let msg = McpServer::parse_incoming(input).expect("a lone object parses");
        assert_eq!(msg.method.as_deref(), Some("initialize"));
        assert_eq!(msg.id, Some(serde_json::json!(1)));
    }

    /// Supersedes `test_parse_incoming_batch`, which asserted that a
    /// two-element array parsed into two messages.
    ///
    /// JSON-RPC batching was removed in revision 2025-06-18 and 2026-07-28
    /// does not restore it: `JSONRPCMessage` has three object forms and no
    /// array form, and "batch" appears nowhere in the published schema.
    ///
    /// The CODE assertion is what matters, not merely that it errors.
    /// `-32600 Invalid Request` says the JSON was fine and the shape was not;
    /// `-32700 Parse error` would tell a client its JSON was malformed, which
    /// is false and sends it looking in the wrong place. `test_parse_incoming
    /// _invalid_json` below holds the other end of that distinction, so
    /// neither test can be satisfied by a function that returns one code for
    /// everything.
    #[test]
    fn a_json_array_is_refused_as_invalid_request_not_a_parse_error() {
        let input = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"resources/list"}]"#;
        let err = McpServer::parse_incoming(input).expect_err("batching was removed in 2025-06-18");
        assert_eq!(err.code, -32600, "{}", err.message);
        assert!(err.message.contains("batching"), "{}", err.message);
    }

    /// `[]` is the case most likely to be waved through as harmless — it
    /// carries no messages, so nothing would execute either way. It is
    /// refused for the same reason as a populated array: the array form is
    /// not a thing this protocol has, and accepting the empty one would leave
    /// `parse_incoming` with a shape it has to model.
    #[test]
    fn an_empty_json_array_is_refused_too() {
        let err = McpServer::parse_incoming("[]").expect_err("there is no array form at all");
        assert_eq!(err.code, -32600, "{}", err.message);
    }

    /// Leading whitespace must not smuggle an array past the check — the
    /// guard trims before testing the first byte, and this is what pins that
    /// it still does.
    #[test]
    fn an_array_behind_leading_whitespace_is_still_refused() {
        let err = McpServer::parse_incoming("   [{\"jsonrpc\":\"2.0\",\"id\":1}]")
            .expect_err("whitespace is not a bypass");
        assert_eq!(err.code, -32600, "{}", err.message);
    }

    #[test]
    fn test_parse_incoming_notification() {
        let input = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let msg = McpServer::parse_incoming(input).expect("a notification parses");
        assert_eq!(msg.method.as_deref(), Some("notifications/initialized"));
        assert!(msg.id.is_none());
    }

    #[test]
    fn test_parse_incoming_invalid_json() {
        let err = McpServer::parse_incoming("not valid json{{{").expect_err("malformed");
        assert_eq!(
            err.code, -32700,
            "malformed JSON is a parse error, not an invalid request: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_incoming_empty_string() {
        let err = McpServer::parse_incoming("").expect_err("an empty line is not a message");
        assert_eq!(err.code, -32700, "{}", err.message);
    }

    #[test]
    fn test_parse_incoming_with_leading_whitespace() {
        let input = "   {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        let msg = McpServer::parse_incoming(input).expect("leading whitespace is trimmed");
        assert_eq!(msg.method.as_deref(), Some("tools/list"));
    }

    #[test]
    fn test_parse_incoming_response_no_method() {
        let valid = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let msg = McpServer::parse_incoming(valid).expect("a client response parses");
        assert!(msg.method.is_none());
        assert_eq!(msg.id, Some(serde_json::json!(1)));
    }

    #[tokio::test]
    async fn test_stdio_transport_shutdown_is_noop() {
        let transport = StdioTransport::new();
        transport.shutdown().await;
    }

    #[test]
    fn test_writer_message_serialization() {
        use crate::mcp::protocol::{JsonRpcResponse, WriterMessage};

        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            result: Some(serde_json::json!({"tools": []})),
            error: None,
        };
        let msg = WriterMessage::Response(Box::new(response));

        let json_str = match &msg {
            WriterMessage::Response(r) => serde_json::to_string(r),
            _ => unreachable!(),
        };
        assert!(json_str.is_ok());
        let s = json_str.unwrap();
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
        assert!(s.contains("\"id\":1"));
    }
}
