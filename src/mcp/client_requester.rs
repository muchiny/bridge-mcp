//! Client Requester
//!
//! Service for sending JSON-RPC requests to the client and awaiting responses.
//! Used by `ElicitationService` and `SamplingService` to implement
//! server-to-client request/response patterns.
//!
//! # THIS ENTIRE MECHANISM IS THE PATTERN 2026-07-28 DELETED
//!
//! It is the largest known non-conformance left in this server, and it is
//! recorded here rather than in a tracker because this file is where someone
//! will look.
//!
//! Multi Round-Trip Requests opens by removing what this module does, in as
//! many words: *"Servers **MUST** send server-to-client requests (such as
//! `roots/list`, `sampling/createMessage`, or `elicitation/create`) using the
//! MRTR pattern. The previous pattern of server-initiated requests is no
//! longer supported. This is a breaking change."*
//! (`/specification/2026-07-28/basic/patterns/mrtr`.) Streamable HTTP says the
//! same from the transport side: *"The server **MUST NOT** send independent
//! JSON-RPC requests on this stream."*
//!
//! MRTR inverts the direction. Instead of the server sending a request and
//! blocking on the reply, it RETURNS `resultType: "input_required"` carrying
//! an `inputRequests` map, and the client re-sends the original call — under a
//! NEW JSON-RPC id, which the spec requires — with `inputResponses` and the
//! opaque `requestState` the server handed back. Nothing is held open, which
//! is the point: it works on a stateless transport with no sticky routing.
//!
//! Two callers are affected, and both are live:
//!
//! - `ElicitationService`, behind `security.require_elicitation_on_destructive`.
//!   This one is a security control, so it is the one that matters: an
//!   operator relying on destructive-op confirmation is relying on a flow no
//!   conforming 2026-07-28 client is obliged to answer.
//! - `McpServer::fetch_roots`, which sends `roots/list` unprompted.
//!
//! Converting is not a rename. `requestState` MUST be treated as
//! attacker-controlled and integrity-protected when it influences
//! authorization (HMAC or AEAD), and SHOULD carry the authenticated principal,
//! a short TTL, and a digest of the originating request, each verified on
//! receipt. That is key management and state encoding, and it changes the
//! client contract of every destructive tool — a piece of work in its own
//! right, not a fix to fold into one.
//!
//! Until then, `task_policy`'s rule 2 holds for this reason: promoting a
//! destructive tool to a task would build confirmation-then-task on top of the
//! deleted flow.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;

use super::pending_requests::{ClientResponse, PendingRequests};
use super::protocol::{JsonRpcOutboundRequest, WriterMessage};

/// Error from a server-to-client request.
#[derive(Debug)]
pub enum ClientRequestError {
    /// Client doesn't support this capability.
    NotSupported,
    /// Writer channel closed.
    ChannelClosed,
    /// Client didn't respond in time.
    Timeout,
    /// Client declined the request (elicitation).
    Declined,
    /// Client cancelled the request (elicitation).
    Cancelled,
    /// Client returned a JSON-RPC error.
    RemoteError { code: i32, message: String },
}

impl std::fmt::Display for ClientRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupported => write!(f, "Client does not support this capability"),
            Self::ChannelClosed => write!(f, "Writer channel closed"),
            Self::Timeout => write!(f, "Client request timed out"),
            Self::Declined => write!(f, "Client declined the request"),
            Self::Cancelled => write!(f, "Client cancelled the request"),
            Self::RemoteError { code, message } => {
                write!(f, "Client error ({code}): {message}")
            }
        }
    }
}

impl std::error::Error for ClientRequestError {}

/// Sends JSON-RPC requests to the client and awaits responses.
pub struct ClientRequester {
    tx: mpsc::Sender<WriterMessage>,
    pending: Arc<PendingRequests>,
    timeout: Duration,
}

impl ClientRequester {
    /// Create a new client requester.
    #[must_use]
    pub fn new(
        tx: mpsc::Sender<WriterMessage>,
        pending: Arc<PendingRequests>,
        timeout: Duration,
    ) -> Self {
        Self {
            tx,
            pending,
            timeout,
        }
    }

    /// Send a JSON-RPC request to the client and wait for the response.
    ///
    /// # Errors
    ///
    /// Returns `ClientRequestError` if the channel is closed, the client
    /// doesn't respond in time, or the client returns an error.
    pub async fn send_request(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, ClientRequestError> {
        let (id, rx) = self.pending.create_request();

        let request = JsonRpcOutboundRequest::new(Value::String(id), method, Some(params));

        self.tx
            .send(WriterMessage::Request(request))
            .await
            .map_err(|_| ClientRequestError::ChannelClosed)?;

        let response = tokio::time::timeout(self.timeout, rx)
            .await
            .map_err(|_| ClientRequestError::Timeout)?
            .map_err(|_| ClientRequestError::ChannelClosed)?;

        match response {
            ClientResponse::Success(value) => Ok(value),
            ClientResponse::Error { code, message, .. } => {
                Err(ClientRequestError::RemoteError { code, message })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_request_timeout() {
        let (tx, _rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = ClientRequester::new(tx, pending, Duration::from_millis(10));

        let result = requester
            .send_request("test/method", serde_json::json!({}))
            .await;
        assert!(matches!(result, Err(ClientRequestError::Timeout)));
    }

    #[tokio::test]
    async fn test_send_request_channel_closed() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx); // Close the channel
        let pending = Arc::new(PendingRequests::new());
        let requester = ClientRequester::new(tx, pending, Duration::from_secs(5));

        let result = requester
            .send_request("test/method", serde_json::json!({}))
            .await;
        assert!(matches!(result, Err(ClientRequestError::ChannelClosed)));
    }

    #[tokio::test]
    async fn test_send_request_success() {
        let (tx, mut rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = ClientRequester::new(tx, Arc::clone(&pending), Duration::from_secs(5));

        // Spawn a "client" that reads the request and responds
        let pending_clone = Arc::clone(&pending);
        tokio::spawn(async move {
            if let Some(WriterMessage::Request(req)) = rx.recv().await {
                let id = req.id.as_str().unwrap().to_string();
                pending_clone.resolve(&id, ClientResponse::Success(serde_json::json!("ok")));
            }
        });

        let result = requester
            .send_request("test/method", serde_json::json!({"key": "value"}))
            .await
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[tokio::test]
    async fn test_send_request_remote_error() {
        let (tx, mut rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = ClientRequester::new(tx, Arc::clone(&pending), Duration::from_secs(5));

        let pending_clone = Arc::clone(&pending);
        tokio::spawn(async move {
            if let Some(WriterMessage::Request(req)) = rx.recv().await {
                let id = req.id.as_str().unwrap().to_string();
                pending_clone.resolve(
                    &id,
                    ClientResponse::Error {
                        code: -1,
                        message: "denied".to_string(),
                        data: None,
                    },
                );
            }
        });

        let result = requester
            .send_request("test/method", serde_json::json!({}))
            .await;
        match result {
            Err(ClientRequestError::RemoteError { code, message }) => {
                assert_eq!(code, -1);
                assert_eq!(message, "denied");
            }
            _ => panic!("Expected RemoteError"),
        }
    }

    // ============== Display trait ==============

    #[test]
    fn test_display_not_supported() {
        let err = ClientRequestError::NotSupported;
        assert_eq!(err.to_string(), "Client does not support this capability");
    }

    #[test]
    fn test_display_channel_closed() {
        let err = ClientRequestError::ChannelClosed;
        assert_eq!(err.to_string(), "Writer channel closed");
    }

    #[test]
    fn test_display_timeout() {
        let err = ClientRequestError::Timeout;
        assert_eq!(err.to_string(), "Client request timed out");
    }

    #[test]
    fn test_display_declined() {
        let err = ClientRequestError::Declined;
        assert_eq!(err.to_string(), "Client declined the request");
    }

    #[test]
    fn test_display_cancelled() {
        let err = ClientRequestError::Cancelled;
        assert_eq!(err.to_string(), "Client cancelled the request");
    }

    #[test]
    fn test_display_remote_error() {
        let err = ClientRequestError::RemoteError {
            code: -32600,
            message: "Invalid Request".to_string(),
        };
        assert_eq!(err.to_string(), "Client error (-32600): Invalid Request");
    }

    #[test]
    fn test_error_trait() {
        use std::error::Error;
        let err = ClientRequestError::Timeout;
        let _: &dyn Error = &err;
        assert!(err.source().is_none());
    }

    #[test]
    fn test_debug_format() {
        let err = ClientRequestError::NotSupported;
        let debug = format!("{err:?}");
        assert!(debug.contains("NotSupported"));
    }

    // ============== Request routing ==============

    #[tokio::test]
    async fn test_send_request_passes_method_and_params() {
        let (tx, mut rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = ClientRequester::new(tx, Arc::clone(&pending), Duration::from_secs(5));

        let pending_clone = Arc::clone(&pending);
        tokio::spawn(async move {
            if let Some(WriterMessage::Request(req)) = rx.recv().await {
                // Verify the request carries the correct method
                assert_eq!(req.method, "elicitation/create");
                let id = req.id.as_str().unwrap().to_string();
                pending_clone.resolve(
                    &id,
                    ClientResponse::Success(serde_json::json!({"ok": true})),
                );
            }
        });

        let result = requester
            .send_request("elicitation/create", serde_json::json!({"field": "value"}))
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({"ok": true}));
    }

    #[tokio::test]
    async fn test_send_request_receiver_dropped_before_resolve() {
        let (tx, mut rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = ClientRequester::new(tx, Arc::clone(&pending), Duration::from_millis(50));

        // Spawn a "client" that reads but never resolves
        tokio::spawn(async move {
            let _ = rx.recv().await;
            // Don't resolve — let the timeout fire
        });

        let result = requester
            .send_request("test/method", serde_json::json!({}))
            .await;
        assert!(matches!(result, Err(ClientRequestError::Timeout)));
    }
}
