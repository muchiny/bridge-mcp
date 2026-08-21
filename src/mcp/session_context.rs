//! Per-session bundled state.
//!
//! Audit 2026-05-09 (FIND-033/034/036/037) moved four fields off the
//! shared `McpServer` and into per-session storage allocated in
//! `serve_session()`. Together with the prior fixes from Vuln 8, Vuln 9,
//! and FIND-038, that adds up to seven Arc/handle parameters threaded
//! through `route_incoming_message → handle_request_with_cancel →
//! handle_tools_call → create_tool_context`. To avoid the parameter
//! explosion (and per the FIND-038 quality review's standing
//! recommendation), this module bundles them into a single
//! [`SessionContext`].
//!
//! Lifetime: a fresh [`SessionContext`] is allocated at the top of
//! `McpServer::serve_session()` and shared by clone (cheap — every
//! field is `Arc`-wrapped) into spawned per-request tasks. Each session
//! owns an independent bundle, so cross-session leakage is impossible
//! by construction.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tokio::sync::{RwLock, mpsc};

use super::pending_requests::PendingRequests;
use super::protocol::{RootEntry, WriterMessage};
use super::request_meta::RequestMeta;
use super::session_capabilities::SessionCapabilities;

/// All per-session state bundled into one cloneable handle.
///
/// Every field is an `Arc`/handle so `Clone` is cheap. Spawned per-request
/// tasks clone the whole bundle to avoid threading 7+ individual
/// parameters through the dispatch chain.
#[derive(Clone)]
pub struct SessionContext {
    /// Per-session pending-requests map (Vuln 8).
    pub pending: Arc<PendingRequests>,
    /// Per-session client capability flags (Vuln 9).
    pub caps: Arc<SessionCapabilities>,
    /// Per-session active-requests map for MCP cancellation (FIND-038).
    pub active_requests: super::server::ActiveRequests,
    /// Per-session writer channel for server-initiated messages
    /// (notifications, requests). FIND-034.
    pub notification_tx: mpsc::Sender<WriterMessage>,
    /// Per-session runtime override for `max_output_chars`. Written by
    /// `handle_initialize` based on this client's `client_overrides`
    /// profile and read by `create_tool_context`. FIND-033.
    pub runtime_max_output: Arc<RwLock<Option<usize>>>,
    /// Per-session client-declared workspace roots. Written by
    /// `fetch_roots` on the session's first client request. FIND-037.
    pub roots: Arc<RwLock<Vec<RootEntry>>>,
    /// One-shot latch: set the first time this session dispatches a
    /// client request, gating the `roots/list` fetch. Modern
    /// (2026-07-28) deleted `notifications/initialized`, which used to
    /// be the trigger.
    pub roots_fetched: Arc<AtomicBool>,
    /// The `_meta` envelope of the ONE request currently being handled
    /// (MCP 2026-07-28). `None` on the session-level bundle and on every
    /// request from a Legacy client.
    ///
    /// This field is deliberately NOT `Arc`-shared with the session:
    /// [`Self::with_request_meta`] clones the bundle and replaces only this
    /// slot, so a per-request envelope can never leak into the session or
    /// into a concurrently running sibling request.
    pub request_meta: Option<Arc<RequestMeta>>,
}

impl SessionContext {
    /// Allocate a fresh per-session bundle, given the writer channel
    /// returned by `serve_session()`'s `mpsc::channel`.
    #[must_use]
    pub fn new(notification_tx: mpsc::Sender<WriterMessage>) -> Self {
        Self {
            pending: Arc::new(PendingRequests::new()),
            caps: Arc::new(SessionCapabilities::new()),
            active_requests: super::server::ActiveRequests::new(),
            notification_tx,
            runtime_max_output: Arc::new(RwLock::new(None)),
            roots: Arc::new(RwLock::new(Vec::new())),
            roots_fetched: Arc::new(AtomicBool::new(false)),
            request_meta: None,
        }
    }

    /// Clone this bundle and attach ONE request's `_meta` envelope.
    ///
    /// Called once per incoming request at the dispatch chokepoint. Every
    /// other field is `Arc`-shared with the original, so the clone is cheap
    /// and session state stays common; only `request_meta` diverges.
    #[must_use]
    pub fn with_request_meta(&self, meta: RequestMeta) -> Self {
        let mut scoped = self.clone();
        scoped.request_meta = Some(Arc::new(meta));
        scoped
    }

    /// Whether the client supports `elicitation/create` for THIS request.
    ///
    /// Precedence — this is the compatibility seam that lets Modern and
    /// Legacy clients coexist while the handshake is being removed:
    /// 1. the request's own `_meta` envelope, when it declared capabilities
    ///    (including an authoritative `{}` meaning "none");
    /// 2. otherwise the flags this session's `initialize` handshake set.
    #[must_use]
    pub fn supports_elicitation(&self) -> bool {
        self.request_meta
            .as_ref()
            .and_then(|m| m.declares_elicitation())
            .unwrap_or_else(|| self.caps.supports_elicitation())
    }

    /// Whether the client supports `sampling/createMessage` for THIS request.
    /// See [`Self::supports_elicitation`] for the precedence rule.
    #[must_use]
    pub fn supports_sampling(&self) -> bool {
        self.request_meta
            .as_ref()
            .and_then(|m| m.declares_sampling())
            .unwrap_or_else(|| self.caps.supports_sampling())
    }

    /// Whether the client supports `roots/list` for THIS request.
    /// See [`Self::supports_elicitation`] for the precedence rule.
    #[must_use]
    pub fn supports_roots(&self) -> bool {
        self.request_meta
            .as_ref()
            .and_then(|m| m.declares_roots())
            .unwrap_or_else(|| self.caps.supports_roots())
    }

    /// The client name declared in THIS request's `_meta` envelope.
    ///
    /// Modern clients never send `initialize`, so this is the only place a
    /// client name is available once the handshake is gone.
    #[must_use]
    pub fn request_client_name(&self) -> Option<&str> {
        self.request_meta.as_ref().and_then(|m| m.client_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_writer_tx() -> mpsc::Sender<WriterMessage> {
        let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
        tx
    }

    #[tokio::test]
    async fn session_context_new_initializes_default_state() {
        let tx = dummy_writer_tx();
        let ctx = SessionContext::new(tx);

        // All map/list state empty on construction.
        assert!(ctx.runtime_max_output.read().await.is_none());
        assert!(ctx.roots.read().await.is_empty());
    }

    #[tokio::test]
    async fn session_context_clone_shares_inner_state() {
        let tx = dummy_writer_tx();
        let a = SessionContext::new(tx);
        let b = a.clone();

        // Mutating Arc-wrapped state through clone B is visible from A.
        *b.runtime_max_output.write().await = Some(4096);
        assert_eq!(*a.runtime_max_output.read().await, Some(4096));
    }

    #[test]
    fn request_meta_defaults_to_absent() {
        let ctx = SessionContext::new(dummy_writer_tx());
        assert!(ctx.request_meta.is_none());
        assert!(ctx.request_client_name().is_none());
        // With neither handshake nor envelope, everything is false.
        assert!(!ctx.supports_elicitation());
        assert!(!ctx.supports_sampling());
        assert!(!ctx.supports_roots());
    }

    #[test]
    fn per_request_meta_grants_capability_without_any_handshake() {
        // This is the compatibility seam: no `initialize` ever ran, so every
        // SessionCapabilities AtomicBool is false, yet the request's own
        // `_meta` envelope declares elicitation.
        let base = SessionContext::new(dummy_writer_tx());
        assert!(!base.caps.supports_elicitation());

        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} },
                "io.modelcontextprotocol/clientInfo": {
                    "name": "ExampleClient",
                    "version": "1.0.0"
                }
            }
        });
        let scoped = base.with_request_meta(RequestMeta::from_params(Some(&params)));

        assert!(scoped.supports_elicitation());
        assert!(!scoped.supports_sampling());
        assert!(!scoped.supports_roots());
        assert_eq!(scoped.request_client_name(), Some("ExampleClient"));
    }

    #[test]
    fn absent_envelope_falls_back_to_handshake_flags() {
        // Legacy client: `initialize` set the flags, requests carry no `_meta`.
        let base = SessionContext::new(dummy_writer_tx());
        base.caps.set_supports_elicitation(true);

        let params = serde_json::json!({ "name": "ssh_exec" });
        let scoped = base.with_request_meta(RequestMeta::from_params(Some(&params)));

        assert!(scoped.supports_elicitation());
    }

    #[test]
    fn declared_envelope_overrides_handshake_flags() {
        // Modern client that supports nothing: `{}` is an authoritative
        // denial for THIS request and must win over a stale handshake flag.
        let base = SessionContext::new(dummy_writer_tx());
        base.caps.set_supports_elicitation(true);
        base.caps.set_supports_sampling(true);

        let params = serde_json::json!({
            "_meta": { "io.modelcontextprotocol/clientCapabilities": {} }
        });
        let scoped = base.with_request_meta(RequestMeta::from_params(Some(&params)));

        assert!(!scoped.supports_elicitation());
        assert!(!scoped.supports_sampling());
    }

    #[tokio::test]
    async fn with_request_meta_does_not_mutate_the_session() {
        let base = SessionContext::new(dummy_writer_tx());
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/clientCapabilities": { "elicitation": {} }
            }
        });
        let scoped = base.with_request_meta(RequestMeta::from_params(Some(&params)));

        // The per-request slot is NOT shared: the session and any sibling
        // request clone still see no envelope.
        assert!(scoped.request_meta.is_some());
        assert!(base.request_meta.is_none());
        assert!(!base.supports_elicitation());

        // The Arc-wrapped state IS still shared, as before.
        *scoped.runtime_max_output.write().await = Some(4096);
        assert_eq!(*base.runtime_max_output.read().await, Some(4096));
    }
}
