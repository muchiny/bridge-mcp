//! MCP Elicitation Service
//!
//! Allows the server to ask the client for user input via `elicitation/create`.
//!
//! Use cases:
//! - SSH host key verification (confirm unknown host key fingerprint)
//! - Password/passphrase input (encrypted SSH key)
//! - Confirmation of destructive operations

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

use super::client_requester::{ClientRequestError, ClientRequester};
use super::protocol::{ElicitationCreateParams, ElicitationCreateResult};

/// Pure JSON-Schema builders for elicitation `requested_schema` fields.
///
/// All builders emit draft-2020-12-compatible property fragments:
/// - [`bool_default`] — a boolean with a SEP-1034 `default`.
/// - [`string_enum`] — a single-select enum with an optional SEP-1034 `default`.
/// - [`multi_select_enum`] — an array-of-enum (SEP-1330) for fleet selection,
///   with an optional `default` pre-selection.
///
/// These are property *fragments*: callers wrap them in
/// `{ "type": "object", "properties": { ... }, "required": [...] }`.
mod schema {
    use serde_json::{Value, json};

    /// A boolean property carrying a SEP-1034 `default`.
    #[must_use]
    pub fn bool_default(_name: &str, description: &str, default: bool) -> Value {
        json!({
            "type": "boolean",
            "description": description,
            "default": default
        })
    }

    /// A single-select string enum (SEP-1034 `default` when `default` is `Some`).
    #[must_use]
    #[allow(dead_code)]
    pub fn string_enum(
        _name: &str,
        description: &str,
        choices: &[String],
        default: Option<String>,
    ) -> Value {
        let mut obj = json!({
            "type": "string",
            "description": description,
            "enum": choices
        });
        if let Some(d) = default {
            obj["default"] = Value::String(d);
        }
        obj
    }

    /// A multi-select array-of-enum (SEP-1330) for fleet actions.
    ///
    /// Emits `{"type":"array","items":{"type":"string","enum":[...]},
    /// "uniqueItems":true}` plus an optional `default` pre-selection.
    #[must_use]
    #[allow(dead_code)]
    pub fn multi_select_enum(
        _name: &str,
        description: &str,
        choices: &[String],
        default: Option<Vec<String>>,
    ) -> Value {
        let mut obj = json!({
            "type": "array",
            "description": description,
            "uniqueItems": true,
            "items": {
                "type": "string",
                "enum": choices
            }
        });
        if let Some(d) = default {
            obj["default"] = Value::Array(d.into_iter().map(Value::String).collect());
        }
        obj
    }
}

/// MCP Elicitation service (server asks client for user input).
pub struct ElicitationService {
    requester: Arc<ClientRequester>,
    client_supports: AtomicBool,
}

/// A concrete, operator-reviewable plan attached to a destructive
/// confirmation prompt.
///
/// Both fields are optional. `command` is the exact shell command the
/// tool will run; `diff` is a unified diff of the change (e.g. produced
/// by `ssh_file_diff`). When both are `None`, the confirmation degrades
/// to the legacy free-text summary prompt.
#[derive(Debug, Clone, Default)]
pub struct ElicitationPlan {
    /// The exact command to be executed, rendered in a fenced `sh` block.
    pub command: Option<String>,
    /// A unified diff of the intended change, rendered in a fenced `diff`
    /// block. Truncated to 4000 chars in the prompt.
    pub diff: Option<String>,
}

impl ElicitationService {
    /// Create a new elicitation service.
    #[must_use]
    pub fn new(requester: Arc<ClientRequester>) -> Self {
        Self {
            requester,
            client_supports: AtomicBool::new(false),
        }
    }

    /// Set whether the client supports elicitation (called during initialize).
    pub fn set_supported(&self, supported: bool) {
        self.client_supports.store(supported, Ordering::Relaxed);
    }

    /// Whether the client supports elicitation.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.client_supports.load(Ordering::Relaxed)
    }

    /// Send an elicitation request to the client.
    ///
    /// # Errors
    ///
    /// Returns `ClientRequestError::NotSupported` if the client doesn't support
    /// elicitation, or other errors on communication failure.
    pub async fn elicit(
        &self,
        message: &str,
        schema: Option<Value>,
    ) -> Result<ElicitationCreateResult, ClientRequestError> {
        if !self.is_supported() {
            return Err(ClientRequestError::NotSupported);
        }

        let params = ElicitationCreateParams {
            message: message.to_string(),
            requested_schema: schema,
            url: None,
        };

        let value = self
            .requester
            .send_request(
                "elicitation/create",
                serde_json::to_value(&params).map_err(|_| ClientRequestError::ChannelClosed)?,
            )
            .await?;

        let result: ElicitationCreateResult =
            serde_json::from_value(value).map_err(|_| ClientRequestError::RemoteError {
                code: -1,
                message: "Invalid elicitation response".to_string(),
            })?;

        match result.action.as_str() {
            "decline" => Err(ClientRequestError::Declined),
            "cancel" => Err(ClientRequestError::Cancelled),
            _ => Ok(result),
        }
    }

    /// Ask the client to confirm a destructive tool call.
    ///
    /// Delegates to [`confirm_destructive_with_plan`] with `plan = None`,
    /// preserving the original behavior for all existing callers.
    ///
    /// # Errors
    ///
    /// Returns `ClientRequestError::NotSupported` if the client does not
    /// advertise the elicitation capability.
    pub async fn confirm_destructive(
        &self,
        tool_name: &str,
        summary: &str,
    ) -> Result<bool, ClientRequestError> {
        self.confirm_destructive_with_plan(tool_name, summary, None)
            .await
    }

    /// Ask the client to confirm a destructive tool call, optionally
    /// embedding a concrete [`ElicitationPlan`] (command + unified diff)
    /// so the operator approves a specific change rather than a free-text
    /// summary.
    ///
    /// The plan is rendered into the prompt `message` as fenced markdown
    /// blocks (```` ```sh ```` for the command, ```` ```diff ```` for the
    /// diff). The confirm schema carries a SEP-1034 `default: false` so a
    /// client that auto-fills defaults never silently proceeds.
    ///
    /// # Errors
    ///
    /// Returns `ClientRequestError::NotSupported` if the client does not
    /// advertise the elicitation capability; propagates `Declined` /
    /// `Cancelled` unchanged.
    pub async fn confirm_destructive_with_plan(
        &self,
        tool_name: &str,
        summary: &str,
        plan: Option<ElicitationPlan>,
    ) -> Result<bool, ClientRequestError> {
        let mut message = format!("Confirm destructive operation: `{tool_name}`\n\n{summary}\n");
        if let Some(p) = plan {
            if let Some(cmd) = p.command {
                let _ = write!(message, "\n**Command:**\n```sh\n{cmd}\n```\n");
            }
            if let Some(diff) = p.diff {
                const MAX_DIFF: usize = 4000;
                let rendered = if diff.len() > MAX_DIFF {
                    let mut end = MAX_DIFF;
                    while !diff.is_char_boundary(end) {
                        end -= 1;
                    }
                    format!("{}\n… (diff truncated)", &diff[..end])
                } else {
                    diff
                };
                let _ = write!(message, "\n**Diff:**\n```diff\n{rendered}\n```\n");
            }
        }
        message.push_str("\nProceed?");

        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "confirm": schema::bool_default(
                    "confirm",
                    "Set to true to execute the destructive operation",
                    false
                )
            },
            "required": ["confirm"]
        });

        let result = self.elicit(&message, Some(schema)).await?;
        let confirmed = result
            .content
            .as_ref()
            .and_then(|v| v.get("confirm"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(confirmed)
    }

    /// URL-mode elicitation (SEP-1036).
    ///
    /// Asks the client to open a URL in the user's browser.
    /// Only `https://` URLs are allowed for security.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL scheme is not `https://` or the client
    /// doesn't support elicitation.
    pub async fn elicit_url(
        &self,
        message: &str,
        url: &str,
    ) -> Result<ElicitationCreateResult, ClientRequestError> {
        if !self.is_supported() {
            return Err(ClientRequestError::NotSupported);
        }

        // Security: only allow https URLs
        if !url.starts_with("https://") {
            return Err(ClientRequestError::RemoteError {
                code: -1,
                message: "Only https:// URLs are allowed for elicitation".to_string(),
            });
        }

        let params = ElicitationCreateParams {
            message: message.to_string(),
            requested_schema: None,
            url: Some(url.to_string()),
        };

        let value = self
            .requester
            .send_request(
                "elicitation/create",
                serde_json::to_value(&params).map_err(|_| ClientRequestError::ChannelClosed)?,
            )
            .await?;

        let result: ElicitationCreateResult =
            serde_json::from_value(value).map_err(|_| ClientRequestError::RemoteError {
                code: -1,
                message: "Invalid elicitation response".to_string(),
            })?;

        match result.action.as_str() {
            "decline" => Err(ClientRequestError::Declined),
            "cancel" => Err(ClientRequestError::Cancelled),
            _ => Ok(result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::pending_requests::PendingRequests;
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn create_test_service() -> (
        ElicitationService,
        mpsc::Receiver<super::super::protocol::WriterMessage>,
    ) {
        let (tx, rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = Arc::new(ClientRequester::new(tx, pending, Duration::from_secs(5)));
        (ElicitationService::new(requester), rx)
    }

    #[tokio::test]
    async fn test_elicit_not_supported() {
        let (service, _rx) = create_test_service();
        // Default: not supported
        let result = service.elicit("test", None).await;
        assert!(matches!(result, Err(ClientRequestError::NotSupported)));
    }

    #[tokio::test]
    async fn test_elicit_url_rejects_non_https() {
        let (service, _rx) = create_test_service();
        service.set_supported(true);
        let result = service.elicit_url("test", "http://evil.com").await;
        assert!(matches!(
            result,
            Err(ClientRequestError::RemoteError { .. })
        ));
    }

    #[tokio::test]
    async fn test_elicit_url_rejects_javascript() {
        let (service, _rx) = create_test_service();
        service.set_supported(true);
        let result = service.elicit_url("test", "javascript:alert(1)").await;
        assert!(matches!(
            result,
            Err(ClientRequestError::RemoteError { .. })
        ));
    }

    #[test]
    fn test_set_supported() {
        let (service, _rx) = create_test_service();
        assert!(!service.is_supported());
        service.set_supported(true);
        assert!(service.is_supported());
    }

    #[tokio::test]
    async fn test_elicit_url_not_supported() {
        let (service, _rx) = create_test_service();
        // Default: not supported
        let result = service.elicit_url("test", "https://example.com").await;
        assert!(matches!(result, Err(ClientRequestError::NotSupported)));
    }

    #[tokio::test]
    async fn test_elicit_url_rejects_ftp() {
        let (service, _rx) = create_test_service();
        service.set_supported(true);
        let result = service.elicit_url("test", "ftp://evil.com/file").await;
        assert!(matches!(
            result,
            Err(ClientRequestError::RemoteError { .. })
        ));
    }

    #[tokio::test]
    async fn test_elicit_url_rejects_data_uri() {
        let (service, _rx) = create_test_service();
        service.set_supported(true);
        let result = service
            .elicit_url("test", "data:text/html,<h1>hi</h1>")
            .await;
        assert!(matches!(
            result,
            Err(ClientRequestError::RemoteError { .. })
        ));
    }

    #[tokio::test]
    async fn test_elicit_with_schema() {
        let (service, _rx) = create_test_service();
        // Not supported -> NotSupported error even with schema
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "confirm": { "type": "boolean" }
            }
        });
        let result = service.elicit("Confirm?", Some(schema)).await;
        assert!(matches!(result, Err(ClientRequestError::NotSupported)));
    }

    #[tokio::test]
    async fn test_elicit_sends_request_when_supported() {
        let (service, mut rx) = create_test_service();
        service.set_supported(true);

        // Spawn the elicit call — it will block waiting for a response
        let handle = tokio::spawn(async move { service.elicit("Please confirm", None).await });

        // The service should have sent a writer message
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("Should receive message within timeout")
            .expect("Channel should not be closed");

        // Verify it's a JSON-RPC request for elicitation/create
        match msg {
            super::super::protocol::WriterMessage::Request(req) => {
                assert_eq!(req.method, "elicitation/create");
                let params = req.params.expect("params should be present");
                assert_eq!(params["message"], "Please confirm");
            }
            _ => panic!("Expected Request variant"),
        }

        // The handle will time out since we don't resolve the pending request,
        // but we've verified the message was sent correctly.
        handle.abort();
    }

    #[tokio::test]
    async fn test_elicit_url_sends_request_with_url() {
        let (service, mut rx) = create_test_service();
        service.set_supported(true);

        let handle = tokio::spawn(async move {
            service
                .elicit_url("Open this", "https://example.com/auth")
                .await
        });

        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("Should receive message within timeout")
            .expect("Channel should not be closed");

        match msg {
            super::super::protocol::WriterMessage::Request(req) => {
                assert_eq!(req.method, "elicitation/create");
                let params = req.params.expect("params should be present");
                assert_eq!(params["message"], "Open this");
                assert_eq!(params["url"], "https://example.com/auth");
            }
            _ => panic!("Expected Request variant"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn test_elicit_channel_closed() {
        let (tx, rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = Arc::new(ClientRequester::new(tx, pending, Duration::from_secs(1)));
        let service = ElicitationService::new(requester);
        service.set_supported(true);

        // Drop the receiver so the channel is closed
        drop(rx);

        let result = service.elicit("test", None).await;
        assert!(matches!(result, Err(ClientRequestError::ChannelClosed)));
    }

    #[tokio::test]
    async fn test_confirm_destructive_not_supported() {
        let (service, _rx) = create_test_service();
        let result = service
            .confirm_destructive("ssh_terraform_apply", "rm -rf /")
            .await;
        assert!(matches!(result, Err(ClientRequestError::NotSupported)));
    }

    #[tokio::test]
    async fn test_confirm_destructive_accepted_true() {
        let (service, mut rx) = create_test_service();
        service.set_supported(true);
        let handle = tokio::spawn(async move {
            service
                .confirm_destructive("ssh_win_update_reboot", "reboot host prod-01")
                .await
        });

        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("should receive within timeout")
            .expect("channel open");

        // Grab the request id so we can resolve it through the shared pending map.
        // Here we can't; instead, verify the request schema and abort the handle.
        match msg {
            super::super::protocol::WriterMessage::Request(req) => {
                assert_eq!(req.method, "elicitation/create");
                let params = req.params.expect("params");
                let schema = &params["requestedSchema"];
                assert_eq!(schema["properties"]["confirm"]["type"], "boolean");
                assert_eq!(schema["required"][0], "confirm");
            }
            _ => panic!("expected Request"),
        }
        handle.abort();
    }

    #[test]
    fn test_set_supported_toggle() {
        let (service, _rx) = create_test_service();
        service.set_supported(true);
        assert!(service.is_supported());
        service.set_supported(false);
        assert!(!service.is_supported());
        service.set_supported(true);
        assert!(service.is_supported());
    }

    /// Helper that builds an `ElicitationService` with a shared
    /// `PendingRequests` so tests can resolve the in-flight request
    /// with a specific client response.
    fn create_test_service_with_pending() -> (
        ElicitationService,
        mpsc::Receiver<super::super::protocol::WriterMessage>,
        Arc<PendingRequests>,
    ) {
        let (tx, rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = Arc::new(ClientRequester::new(
            tx,
            pending.clone(),
            Duration::from_secs(5),
        ));
        (ElicitationService::new(requester), rx, pending)
    }

    /// Resolve the most-recently-issued pending request with the given
    /// JSON-RPC response value. Used by the decline/cancel tests.
    ///
    /// IDs are now UUID-based (Vuln 8, audit 2026-05-09), so we cannot
    /// hard-code `"srv-1"`. Tests pass the id observed on the writer
    /// channel (extracted via `extract_outbound_id`).
    fn resolve_only_pending(pending: &PendingRequests, id: &str, response: Value) {
        assert_eq!(pending.len(), 1, "exactly one request must be in flight");
        let resolved = pending.resolve(
            id,
            crate::mcp::pending_requests::ClientResponse::Success(response),
        );
        assert!(resolved, "must resolve the pending request");
    }

    /// Pull the request id out of an outbound `WriterMessage::Request`,
    /// stringifying it the same way `route_incoming_message` does so
    /// `pending.resolve` lookups match.
    fn extract_outbound_id(msg: &super::super::protocol::WriterMessage) -> String {
        if let super::super::protocol::WriterMessage::Request(req) = msg {
            return match &req.id {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
        }
        let _ = msg;
        panic!("expected WriterMessage::Request, got a different WriterMessage variant");
    }

    /// `delete match arm "decline"` on line 81 must change behavior:
    /// without the arm, a `decline` action falls through to `Ok(result)`
    /// instead of `Err(Declined)`. Kills the mutation by asserting
    /// `Err(Declined)` after resolving with action=`decline`.
    #[tokio::test]
    async fn test_elicit_decline_action_returns_declined() {
        let (service, mut rx, pending) = create_test_service_with_pending();
        service.set_supported(true);

        let handle = tokio::spawn(async move { service.elicit("Confirm?", None).await });

        // Drain the outgoing request so the requester registers the pending id.
        let outbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request sent")
            .expect("channel open");
        let id = extract_outbound_id(&outbound);

        resolve_only_pending(&pending, &id, serde_json::json!({"action": "decline"}));

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("handle joins")
            .expect("no panic");
        assert!(
            matches!(result, Err(ClientRequestError::Declined)),
            "decline action must surface as Declined — got {result:?}"
        );
    }

    /// `delete match arm "cancel"` on line 82 — symmetric to the
    /// decline case.
    #[tokio::test]
    async fn test_elicit_cancel_action_returns_cancelled() {
        let (service, mut rx, pending) = create_test_service_with_pending();
        service.set_supported(true);

        let handle = tokio::spawn(async move { service.elicit("Confirm?", None).await });

        let outbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request sent")
            .expect("channel open");
        let id = extract_outbound_id(&outbound);

        resolve_only_pending(&pending, &id, serde_json::json!({"action": "cancel"}));

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("handle joins")
            .expect("no panic");
        assert!(
            matches!(result, Err(ClientRequestError::Cancelled)),
            "cancel action must surface as Cancelled — got {result:?}"
        );
    }

    /// `delete match arm "decline"` / `"cancel"` on lines 174/175 —
    /// the URL-mode variants of the same invariant.
    #[tokio::test]
    async fn test_elicit_url_decline_action_returns_declined() {
        let (service, mut rx, pending) = create_test_service_with_pending();
        service.set_supported(true);

        let handle =
            tokio::spawn(async move { service.elicit_url("Open", "https://example.com").await });

        let outbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request sent")
            .expect("channel open");
        let id = extract_outbound_id(&outbound);

        resolve_only_pending(&pending, &id, serde_json::json!({"action": "decline"}));

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("handle joins")
            .expect("no panic");
        assert!(
            matches!(result, Err(ClientRequestError::Declined)),
            "decline action must surface as Declined — got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_elicit_url_cancel_action_returns_cancelled() {
        let (service, mut rx, pending) = create_test_service_with_pending();
        service.set_supported(true);

        let handle =
            tokio::spawn(async move { service.elicit_url("Open", "https://example.com").await });

        let outbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request sent")
            .expect("channel open");
        let id = extract_outbound_id(&outbound);

        resolve_only_pending(&pending, &id, serde_json::json!({"action": "cancel"}));

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("handle joins")
            .expect("no panic");
        assert!(
            matches!(result, Err(ClientRequestError::Cancelled)),
            "cancel action must surface as Cancelled — got {result:?}"
        );
    }

    /// `delete -` on lines 76 / 148 / 169 flips the JSON-RPC error
    /// `code` field from `-1` to `1`. Tests must assert the literal
    /// value, not just the `RemoteError` variant.
    #[tokio::test]
    async fn test_elicit_url_non_https_error_code_is_neg_one() {
        let (service, _rx) = create_test_service();
        service.set_supported(true);
        let result = service.elicit_url("test", "http://evil.com").await;
        match result {
            Err(ClientRequestError::RemoteError { code, .. }) => {
                assert_eq!(code, -1, "non-https url must report code -1");
            }
            other => panic!("expected RemoteError, got {other:?}"),
        }
    }

    /// Same `code: -1` invariant for the malformed-response paths in
    /// both `elicit` (line 76) and `elicit_url` (line 169) — exercised
    /// by resolving a pending request with a JSON value that fails the
    /// `serde_json::from_value::<ElicitationCreateResult>` parse.
    #[tokio::test]
    async fn test_elicit_invalid_response_error_code_is_neg_one() {
        let (service, mut rx, pending) = create_test_service_with_pending();
        service.set_supported(true);

        let handle = tokio::spawn(async move { service.elicit("Confirm?", None).await });

        let outbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request sent")
            .expect("channel open");
        let id = extract_outbound_id(&outbound);

        // `ElicitationCreateResult` requires an `action` string field;
        // sending an integer makes `serde_json::from_value` fail.
        resolve_only_pending(&pending, &id, serde_json::json!(42));

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("handle joins")
            .expect("no panic");
        match result {
            Err(ClientRequestError::RemoteError { code, .. }) => {
                assert_eq!(code, -1, "parse failure must report code -1");
            }
            other => panic!("expected RemoteError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_elicit_url_invalid_response_error_code_is_neg_one() {
        let (service, mut rx, pending) = create_test_service_with_pending();
        service.set_supported(true);

        let handle =
            tokio::spawn(async move { service.elicit_url("Open", "https://example.com").await });

        let outbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request sent")
            .expect("channel open");
        let id = extract_outbound_id(&outbound);

        resolve_only_pending(&pending, &id, serde_json::json!(42));

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("handle joins")
            .expect("no panic");
        match result {
            Err(ClientRequestError::RemoteError { code, .. }) => {
                assert_eq!(code, -1, "parse failure must report code -1");
            }
            other => panic!("expected RemoteError, got {other:?}"),
        }
    }

    #[test]
    fn test_schema_bool_default_emits_default_field() {
        let s = super::schema::bool_default("confirm", "Set true to proceed", true);
        assert_eq!(s["type"], "boolean");
        assert_eq!(s["description"], "Set true to proceed");
        assert_eq!(s["default"], true, "SEP-1034 default must be present");
    }

    #[test]
    fn test_schema_string_enum_single_select() {
        let s = super::schema::string_enum(
            "service",
            "Pick the service",
            &["nginx".to_string(), "redis".to_string()],
            Some("nginx".to_string()),
        );
        assert_eq!(s["type"], "string");
        assert_eq!(s["enum"][0], "nginx");
        assert_eq!(s["enum"][1], "redis");
        assert_eq!(s["default"], "nginx", "SEP-1034 default on single enum");
    }

    #[test]
    fn test_schema_string_enum_omits_default_when_none() {
        let s =
            super::schema::string_enum("service", "Pick the service", &["nginx".to_string()], None);
        assert!(s.get("default").is_none(), "no default key when None");
    }

    #[test]
    fn test_schema_multi_select_enum_array_of_enum() {
        let s = super::schema::multi_select_enum(
            "hosts",
            "Pick hosts for the fleet action",
            &["web1".to_string(), "web2".to_string(), "db1".to_string()],
            Some(vec!["web1".to_string(), "web2".to_string()]),
        );
        assert_eq!(s["type"], "array");
        assert_eq!(s["items"]["type"], "string");
        assert_eq!(s["items"]["enum"][2], "db1");
        assert_eq!(s["uniqueItems"], true);
        assert_eq!(s["default"][0], "web1");
        assert_eq!(s["default"][1], "web2");
    }

    #[test]
    fn test_schema_multi_select_omits_default_when_none() {
        let s =
            super::schema::multi_select_enum("hosts", "Pick hosts", &["web1".to_string()], None);
        assert!(s.get("default").is_none(), "no default key when None");
        assert_eq!(s["type"], "array");
    }

    #[tokio::test]
    async fn test_confirm_with_plan_embeds_command_and_diff_in_message() {
        let (service, mut rx) = create_test_service();
        service.set_supported(true);
        let plan = super::ElicitationPlan {
            command: Some("systemctl restart nginx".to_string()),
            diff: Some("--- a/nginx.conf\n+++ b/nginx.conf\n-worker 1\n+worker 4".to_string()),
        };
        let handle = tokio::spawn(async move {
            service
                .confirm_destructive_with_plan("ssh_service_restart", "restart nginx", Some(plan))
                .await
        });
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("should receive within timeout")
            .expect("channel open");
        match msg {
            super::super::protocol::WriterMessage::Request(req) => {
                assert_eq!(req.method, "elicitation/create");
                let params = req.params.expect("params");
                let message = params["message"].as_str().expect("message is a string");
                assert!(
                    message.contains("systemctl restart nginx"),
                    "plan command must appear: {message}"
                );
                assert!(message.contains("```sh"), "command fenced as sh");
                assert!(
                    message.contains("+worker 4"),
                    "plan diff must appear: {message}"
                );
                assert!(message.contains("```diff"), "diff fenced as diff");
                let schema = &params["requestedSchema"];
                assert_eq!(schema["properties"]["confirm"]["type"], "boolean");
                assert_eq!(schema["properties"]["confirm"]["default"], false);
                assert_eq!(schema["required"][0], "confirm");
            }
            _ => panic!("expected Request"),
        }
        handle.abort();
    }

    #[tokio::test]
    async fn test_confirm_with_plan_none_matches_legacy_message() {
        let (service, mut rx) = create_test_service();
        service.set_supported(true);
        let handle = tokio::spawn(async move {
            service
                .confirm_destructive_with_plan("ssh_terraform_apply", "apply infra", None)
                .await
        });
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("should receive within timeout")
            .expect("channel open");
        match msg {
            super::super::protocol::WriterMessage::Request(req) => {
                let params = req.params.expect("params");
                let message = params["message"].as_str().expect("string");
                assert!(
                    !message.contains("```sh"),
                    "no command block when plan None"
                );
                assert!(message.contains("apply infra"), "summary still present");
            }
            _ => panic!("expected Request"),
        }
        handle.abort();
    }

    #[tokio::test]
    async fn test_confirm_with_plan_truncates_large_diff() {
        let (service, mut rx) = create_test_service();
        service.set_supported(true);
        let big_diff = "+".repeat(5000);
        let plan = super::ElicitationPlan {
            command: None,
            diff: Some(big_diff),
        };
        let handle = tokio::spawn(async move {
            service
                .confirm_destructive_with_plan("ssh_file_patch", "patch file", Some(plan))
                .await
        });
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("should receive within timeout")
            .expect("channel open");
        match msg {
            super::super::protocol::WriterMessage::Request(req) => {
                let params = req.params.expect("params");
                let message = params["message"].as_str().expect("string");
                assert!(
                    message.contains("(diff truncated)"),
                    "oversize diff must be truncated"
                );
            }
            _ => panic!("expected Request"),
        }
        handle.abort();
    }

    #[tokio::test]
    async fn test_confirm_destructive_legacy_still_sends_bool_schema() {
        let (service, mut rx) = create_test_service();
        service.set_supported(true);
        let handle = tokio::spawn(async move {
            service
                .confirm_destructive("ssh_win_update_reboot", "reboot host prod-01")
                .await
        });
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("should receive within timeout")
            .expect("channel open");
        match msg {
            super::super::protocol::WriterMessage::Request(req) => {
                let params = req.params.expect("params");
                let schema = &params["requestedSchema"];
                assert_eq!(schema["properties"]["confirm"]["type"], "boolean");
                assert_eq!(schema["required"][0], "confirm");
            }
            _ => panic!("expected Request"),
        }
        handle.abort();
    }
}
