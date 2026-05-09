//! Pending Requests
//!
//! Manages server-to-client requests and their pending responses.
//! When the server sends a request to the client (elicitation/sampling),
//! it registers a oneshot sender here. When the client sends a response,
//! the main loop routes it to the correct sender via this map.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::Value;
use tokio::sync::oneshot;

/// Response from the client to a server-initiated request.
#[derive(Debug)]
pub enum ClientResponse {
    /// Successful response with result value.
    Success(Value),
    /// Error response from client.
    Error {
        code: i32,
        message: String,
        data: Option<Value>,
    },
}

/// Tracks server-to-client requests awaiting responses.
pub struct PendingRequests {
    pending: Mutex<HashMap<String, oneshot::Sender<ClientResponse>>>,
}

impl PendingRequests {
    /// Create a new empty pending requests tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new pending request. Returns (`request_id`, receiver).
    ///
    /// IDs are `"srv-{uuid_v4_simple}"` — unguessable and unique. Combined with
    /// the per-session allocation (Vuln 8 audit 2026-05-09) this prevents one
    /// client from resolving another client's pending server-initiated request.
    pub fn create_request(&self) -> (String, oneshot::Receiver<ClientResponse>) {
        let id = format!("srv-{}", uuid::Uuid::new_v4().simple());
        let (tx, rx) = oneshot::channel();

        let mut pending = self.pending.lock().expect("pending lock poisoned");
        pending.insert(id.clone(), tx);

        (id, rx)
    }

    /// Resolve a pending request with a client response.
    ///
    /// Returns `true` if the request was found and resolved.
    pub fn resolve(&self, id: &str, response: ClientResponse) -> bool {
        let mut pending = self.pending.lock().expect("pending lock poisoned");
        if let Some(tx) = pending.remove(id) {
            // If the receiver was dropped, that's fine — the caller timed out.
            let _ = tx.send(response);
            true
        } else {
            false
        }
    }

    /// Number of currently pending requests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.lock().expect("pending lock poisoned").len()
    }

    /// Whether there are no pending requests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request_unique_ids() {
        let pr = PendingRequests::new();
        let (id1, _rx1) = pr.create_request();
        let (id2, _rx2) = pr.create_request();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("srv-"));
        assert!(id1.len() >= 32, "id should embed a UUID for unguessability");
        assert_ne!(id1, "srv-1");
    }

    #[test]
    fn test_resolve_predictable_legacy_id_does_not_succeed() {
        let pr = PendingRequests::new();
        let _ = pr.create_request();
        // Legacy ids "srv-1", "srv-2" must not match anything any more.
        assert!(!pr.resolve("srv-1", ClientResponse::Success(serde_json::json!(null))));
        assert!(!pr.resolve("srv-2", ClientResponse::Success(serde_json::json!(null))));
    }

    #[test]
    fn test_resolve_success() {
        let pr = PendingRequests::new();
        let (id, mut rx) = pr.create_request();
        assert_eq!(pr.len(), 1);

        let resolved = pr.resolve(&id, ClientResponse::Success(serde_json::json!("ok")));
        assert!(resolved);
        assert_eq!(pr.len(), 0);

        let response = rx.try_recv().unwrap();
        match response {
            ClientResponse::Success(v) => assert_eq!(v, "ok"),
            ClientResponse::Error { .. } => panic!("Expected success"),
        }
    }

    #[test]
    fn test_resolve_error() {
        let pr = PendingRequests::new();
        let (id, mut rx) = pr.create_request();

        let resolved = pr.resolve(
            &id,
            ClientResponse::Error {
                code: -1,
                message: "declined".to_string(),
                data: None,
            },
        );
        assert!(resolved);

        let response = rx.try_recv().unwrap();
        match response {
            ClientResponse::Error { code, message, .. } => {
                assert_eq!(code, -1);
                assert_eq!(message, "declined");
            }
            ClientResponse::Success(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn test_resolve_unknown_id() {
        let pr = PendingRequests::new();
        let resolved = pr.resolve("srv-999", ClientResponse::Success(serde_json::json!(null)));
        assert!(!resolved);
    }

    #[test]
    fn test_resolve_dropped_receiver() {
        let pr = PendingRequests::new();
        let (id, rx) = pr.create_request();
        drop(rx); // Simulate timeout
        // Should not panic
        let resolved = pr.resolve(&id, ClientResponse::Success(serde_json::json!(null)));
        assert!(resolved);
    }

    #[test]
    fn test_is_empty() {
        let pr = PendingRequests::new();
        assert!(pr.is_empty());
        let (_id, _rx) = pr.create_request();
        assert!(!pr.is_empty());
    }
}
