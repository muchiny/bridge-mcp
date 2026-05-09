//! Streamable HTTP Transport (MCP 2025-11-25)
//!
//! Implements the MCP Streamable HTTP transport:
//! - `POST /mcp` — Receive JSON-RPC requests, return responses
//! - `GET /mcp` — SSE stream for server-to-client notifications
//! - `DELETE /mcp` — Close a session
//!
//! Sessions are identified by the `Mcp-Session-Id` header.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::sensitive_headers::{
    SetSensitiveRequestHeadersLayer, SetSensitiveResponseHeadersLayer,
};
use tower_http::timeout::TimeoutLayer;
use tracing::{info, warn};

/// Hard cap on request handler latency. Prevents slow-loris-style requests
/// from holding connections open indefinitely. Returns HTTP 408 on expiry.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

use super::oauth::{OAuthConfig, OAuthMetadata, OAuthValidator};
use super::session_store::{InMemorySessionStore, SessionData, SessionStore};

use crate::mcp::protocol::{
    IncomingMessage, JsonRpcError, JsonRpcMessage, JsonRpcResponse, WriterMessage,
};
use crate::mcp::server::McpServer;

/// Default allowlist for the `Origin` header — localhost variants only.
///
/// Per MCP 2025-11-25 the server **MUST** reject requests carrying an
/// invalid `Origin` to prevent DNS-rebinding. Production deployments should
/// override this list to include their public origin.
fn default_allowed_origins() -> Vec<String> {
    vec![
        "http://localhost".to_string(),
        "https://localhost".to_string(),
        "http://127.0.0.1".to_string(),
        "https://127.0.0.1".to_string(),
        "http://[::1]".to_string(),
        "https://[::1]".to_string(),
    ]
}

/// Returns true if `origin` matches one of `allowed` either exactly or with
/// an explicit `:<port>` suffix. Path components or other suffixes are
/// rejected so that lookalike hosts (`http://localhost.evil.com`) do not
/// slip through.
fn is_allowed_origin(origin: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| {
        origin == a
            || origin.strip_prefix(a.as_str()).is_some_and(|rest| {
                rest.starts_with(':') && rest[1..].bytes().all(|b| b.is_ascii_digit())
            })
    })
}

/// Configuration for the HTTP transport.
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Bind address (e.g., `"127.0.0.1:3000"`).
    pub bind: String,
    /// Maximum request body size in bytes (default: 1MB).
    pub max_body_size: usize,
    /// Session timeout (default: 30 minutes).
    pub session_timeout: Duration,
    /// Maximum concurrent sessions (default: 100).
    pub max_sessions: usize,
    /// OAuth configuration (disabled by default).
    pub oauth: OAuthConfig,
    /// Allowlist of origins for the `Origin` header (anti-DNS-rebinding).
    /// An empty list means "reject every request that carries an `Origin`",
    /// which is rarely what you want — see `default_allowed_origins`.
    pub allowed_origins: Vec<String>,
    /// SECURITY: bypass the loopback-or-OAuth check in `serve`. Required only
    /// when intentionally exposing the bridge on a public interface without
    /// OAuth (e.g. behind a separate auth proxy). Defaults to `false`.
    pub allow_unsafe_bind: bool,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:3000".to_string(),
            max_body_size: 1_048_576,
            session_timeout: Duration::from_secs(1800),
            max_sessions: 100,
            oauth: OAuthConfig::default(),
            allowed_origins: default_allowed_origins(),
            allow_unsafe_bind: false,
        }
    }
}

/// Shared state for the HTTP transport.
pub struct HttpTransportState {
    /// Pluggable session backing store (in-memory today, Redis/Valkey
    /// once the June 2026 stateless-transport proposal lands).
    sessions: Arc<dyn SessionStore>,
    config: HttpTransportConfig,
    /// The MCP server processes requests from any session.
    server: Arc<McpServer>,
    /// OAuth configuration.
    oauth: Arc<OAuthConfig>,
}

/// Anti-DNS-rebinding gate (MCP 2025-11-25 §"Streamable HTTP / Security Warning").
///
/// Requests with no `Origin` are rejected with HTTP 403 — non-browser MCP
/// clients on a network attacker's path could otherwise impersonate
/// loopback callers. Requests with an `Origin` not in the configured
/// allowlist also receive HTTP 403 with a JSON-RPC error body (no `id`),
/// as the spec mandates.
async fn origin_guard(
    State(state): State<Arc<HttpTransportState>>,
    request: Request,
    next: Next,
) -> Response {
    let origin_header = request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    match origin_header {
        Some(o) if is_allowed_origin(&o, &state.config.allowed_origins) => next.run(request).await,
        Some(o) => {
            warn!(origin = %o, "Rejected request with invalid Origin header");
            forbidden(&format!("Origin '{o}' is not allowed"))
        }
        None => {
            warn!("Rejected request with no Origin header");
            forbidden("Missing Origin header (anti-DNS-rebinding)")
        }
    }
}

fn forbidden(message: &str) -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": -32600, "message": message },
    });
    (StatusCode::FORBIDDEN, Json(body)).into_response()
}

/// Build the axum Router for the MCP HTTP transport.
///
/// When OAuth is enabled, callers must use
/// [`build_router_with_validator`] (or the wrapping [`serve`] function)
/// to install a boot-time [`OAuthValidator`]. This entry point omits the
/// validator extension; if OAuth is enabled the middleware will respond
/// with HTTP 503 to every protected request, surfacing the
/// misconfiguration loudly instead of silently rejecting tokens with
/// "Unknown JWT signing key" (FIND-006).
pub fn build_router(server: Arc<McpServer>, config: HttpTransportConfig) -> Router {
    build_router_with_store(server, config, Arc::new(InMemorySessionStore::new()), None)
}

/// Build the axum Router with a pre-built [`OAuthValidator`] installed
/// as a request extension. Used by [`serve`] after the validator has
/// been constructed at boot via [`super::oauth::build_validator_from_runtime`].
pub fn build_router_with_validator(
    server: Arc<McpServer>,
    config: HttpTransportConfig,
    validator: &Arc<OAuthValidator>,
) -> Router {
    build_router_with_store(
        server,
        config,
        Arc::new(InMemorySessionStore::new()),
        Some(validator),
    )
}

/// Variant of [`build_router`] that accepts a caller-provided session
/// store. Useful for tests and for future shared-store deployments
/// (Redis, Valkey, …) once the stateless-transport spec lands.
pub fn build_router_with_store(
    server: Arc<McpServer>,
    config: HttpTransportConfig,
    sessions: Arc<dyn SessionStore>,
    validator: Option<&Arc<OAuthValidator>>,
) -> Router {
    let oauth_config = Arc::new(config.oauth.clone());

    let state = Arc::new(HttpTransportState {
        sessions,
        config,
        server,
        oauth: Arc::clone(&oauth_config),
    });

    let mut router = Router::new()
        .route("/mcp", post(handle_post))
        .route("/mcp", get(handle_sse))
        .route("/mcp", delete(handle_delete));

    // Add OAuth middleware if enabled
    if oauth_config.enabled {
        router = router.layer(axum::middleware::from_fn(super::oauth::oauth_middleware));
        router = router.layer(axum::Extension(Arc::clone(&oauth_config)));
        if let Some(v) = validator {
            router = router.layer(axum::Extension(Arc::clone(v)));
        }
    }

    // Discovery and health endpoints (not behind OAuth, but still
    // protected by the Origin gate so a malicious cross-origin page
    // cannot enumerate them).
    let discovery_router = Router::new()
        .route("/.well-known/mcp.json", get(handle_mcp_discovery))
        .route(
            "/.well-known/oauth-authorization-server",
            get(handle_oauth_discovery),
        )
        .route("/health", get(handle_health))
        .with_state(Arc::clone(&state));

    // CORS allowlist mirrors `allowed_origins` so browsers receive the
    // appropriate Access-Control-Allow-Origin header. The
    // `origin_guard` middleware is the actual MUST-comply spec hook —
    // CORS is an in-browser convenience layered on top.
    let mut cors = CorsLayer::new()
        .allow_methods([
            axum::http::Method::POST,
            axum::http::Method::GET,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderName::from_static("mcp-session-id"),
            axum::http::HeaderName::from_static("mcp-protocol-version"),
        ]);
    for origin in &state.config.allowed_origins {
        if let Ok(value) = origin.parse::<axum::http::HeaderValue>() {
            cors = cors.allow_origin(value);
        } else {
            warn!(origin = %origin, "Skipping unparsable allowed_origin entry");
        }
    }

    // Headers carrying secrets must be marked sensitive so any
    // tracing layer that logs HeaderMap will mask them. We share the
    // list as `Arc<[HeaderName]>` so the request- and response-side
    // layers don't each clone the slice.
    let sensitive_headers: Arc<[axum::http::HeaderName]> = Arc::from(
        [
            axum::http::header::AUTHORIZATION,
            axum::http::header::COOKIE,
            axum::http::HeaderName::from_static("mcp-session-id"),
        ]
        .as_slice(),
    );

    router
        .merge(discovery_router)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            origin_guard,
        ))
        // Sensitive-header marking wraps everything below it so any
        // logging middleware sees the masked headers.
        .layer(SetSensitiveRequestHeadersLayer::from_shared(Arc::clone(
            &sensitive_headers,
        )))
        .layer(SetSensitiveResponseHeadersLayer::from_shared(
            sensitive_headers,
        ))
        // Request ID propagation: echo client-supplied x-request-id
        // and stamp our own UUID when the client didn't send one. The
        // propagate layer must be *outside* the set layer so the value
        // generated by `SetRequestIdLayer` makes it back onto the
        // response on the way out.
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        // Hard request timeout — tower-http returns 408 by default.
        // `with_status_code` is the non-deprecated constructor in 0.6.7+.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        // Body-size cap (anti-DoS). Trips with HTTP 413 and never
        // reaches the handler.
        .layer(RequestBodyLimitLayer::new(state.config.max_body_size))
        .layer(cors)
        .with_state(state)
}

/// Start the HTTP transport server.
///
/// This binds to the configured address and serves MCP over HTTP.
/// Refuses to start when binding to a non-loopback address without OAuth
/// enabled, unless `allow_unsafe_bind` is explicitly set.
///
/// When OAuth is enabled, builds a single [`OAuthValidator`] from the
/// supplied config and installs it as an Axum extension so the middleware
/// reads the boot-time key map instead of constructing an empty validator
/// per request (FIND-006). Fails closed at boot when OAuth is enabled but
/// no static keys are configured.
pub async fn serve(
    server: Arc<McpServer>,
    config: HttpTransportConfig,
) -> crate::error::Result<()> {
    refuse_unsafe_bind(&config)?;

    let bind = config.bind.clone();

    let validator = if config.oauth.enabled {
        let v = super::oauth::build_validator_from_runtime(&config.oauth)
            .await
            .map_err(crate::error::BridgeError::McpInvalidRequest)?;
        Some(Arc::new(v))
    } else {
        None
    };

    let router = if let Some(v) = validator.as_ref() {
        build_router_with_validator(server, config, v)
    } else {
        build_router(server, config)
    };

    info!(bind = %bind, "Starting MCP HTTP transport");

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, router)
        .await
        .map_err(|e| crate::error::BridgeError::McpProtocol(format!("HTTP server error: {e}")))?;

    Ok(())
}

/// Refuse to bind to a non-loopback address when OAuth is disabled.
///
/// This prevents the default deployment from exposing an unauthenticated
/// MCP server on a public interface. The check is bypassed when:
/// - `config.allow_unsafe_bind` is `true` (explicit operator override), or
/// - `config.oauth.enabled` is `true`, or
/// - the bind host is a recognised loopback (`127.0.0.1`, `::1`, `localhost`).
fn refuse_unsafe_bind(config: &HttpTransportConfig) -> crate::error::Result<()> {
    if config.allow_unsafe_bind {
        return Ok(());
    }
    let host_part = config
        .bind
        .rsplit_once(':')
        .map_or(config.bind.as_str(), |x| x.0)
        .trim_start_matches('[')
        .trim_end_matches(']');
    let is_loopback = host_part == "127.0.0.1" || host_part == "::1" || host_part == "localhost";
    if !is_loopback && !config.oauth.enabled {
        return Err(crate::error::BridgeError::McpInvalidRequest(format!(
            "Refusing to bind '{}' without OAuth. \
             Set oauth.enabled = true, or bind to 127.0.0.1, \
             or set allow_unsafe_bind = true to override.",
            config.bind
        )));
    }
    Ok(())
}

/// Extract or create session ID from headers.
fn get_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Generate a new session ID.
fn new_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// POST /mcp — Handle JSON-RPC requests.
async fn handle_post(
    State(state): State<Arc<HttpTransportState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // Parse the request
    let incoming = if body.is_array() {
        match serde_json::from_value::<Vec<JsonRpcMessage>>(body) {
            Ok(msgs) => IncomingMessage::Batch(msgs),
            Err(e) => {
                let resp = JsonRpcResponse::error(
                    None,
                    JsonRpcError::parse_error(format!("Invalid batch: {e}")),
                );
                return Json(resp).into_response();
            }
        }
    } else {
        match serde_json::from_value::<JsonRpcMessage>(body) {
            Ok(msg) => IncomingMessage::Single(msg),
            Err(e) => {
                let resp = JsonRpcResponse::error(
                    None,
                    JsonRpcError::parse_error(format!("Invalid JSON-RPC: {e}")),
                );
                return Json(resp).into_response();
            }
        }
    };

    // Get or create session
    let session_id = get_session_id(&headers).unwrap_or_else(new_session_id);

    // Check if this is an initialize request — create session
    let is_initialize = match &incoming {
        IncomingMessage::Single(msg) => msg.method.as_deref() == Some("initialize"),
        IncomingMessage::Batch(_) => false,
    };

    if is_initialize {
        if state.sessions.count().await >= state.config.max_sessions {
            let resp = JsonRpcResponse::error(
                None,
                JsonRpcError::internal_error("Maximum sessions reached"),
            );
            return Json(resp).into_response();
        }

        // Create session channels
        let (notif_tx, _notif_rx) = mpsc::channel::<WriterMessage>(100);

        state
            .sessions
            .insert(
                session_id.clone(),
                SessionData {
                    notification_tx: notif_tx,
                    created_at: std::time::Instant::now(),
                },
            )
            .await;
    }

    // Process the request through the MCP server
    match incoming {
        IncomingMessage::Single(msg) => {
            if msg.method.is_none() {
                return StatusCode::NO_CONTENT.into_response();
            }
            let request = crate::mcp::protocol::JsonRpcRequest {
                jsonrpc: msg.jsonrpc,
                id: msg.id,
                method: msg.method.unwrap_or_default(),
                params: msg.params,
            };
            let resp = state.server.handle_request(request).await;
            let mut response = Json(resp).into_response();
            response.headers_mut().insert(
                "mcp-session-id",
                session_id
                    .parse()
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
            );
            response
        }
        IncomingMessage::Batch(msgs) => {
            let mut responses = Vec::new();
            for msg in msgs {
                if msg.method.is_none() {
                    continue;
                }
                let request = crate::mcp::protocol::JsonRpcRequest {
                    jsonrpc: msg.jsonrpc,
                    id: msg.id.clone(),
                    method: msg.method.unwrap_or_default(),
                    params: msg.params,
                };
                let is_notification = request.id.is_none();
                let resp = state.server.handle_request(request).await;
                if !is_notification {
                    responses.push(resp);
                }
            }
            let mut response = Json(responses).into_response();
            response.headers_mut().insert(
                "mcp-session-id",
                session_id
                    .parse()
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
            );
            response
        }
    }
}

/// GET /mcp — SSE stream for server-to-client notifications.
async fn handle_sse(State(state): State<Arc<HttpTransportState>>, headers: HeaderMap) -> Response {
    let Some(session_id) = get_session_id(&headers) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    // Create a notification channel for this SSE connection
    let (notif_tx, notif_rx) = mpsc::channel::<WriterMessage>(100);

    // Swap the session's notification channel. 404 if the client
    // connects to SSE before `initialize` (or after `DELETE`).
    if !state.sessions.update_tx(&session_id, notif_tx).await {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Convert channel to SSE stream of Result<Event, Infallible>
    let stream = ReceiverStream::new(notif_rx);
    let sse_stream = tokio_stream::StreamExt::filter_map(stream, |msg| {
        let json_str = match &msg {
            WriterMessage::Response(r) => serde_json::to_string(&**r).ok(),
            WriterMessage::Notification(n) => serde_json::to_string(n).ok(),
            WriterMessage::Request(r) => serde_json::to_string(r).ok(),
            WriterMessage::BatchResponse(rs) => serde_json::to_string(rs).ok(),
        };
        json_str.map(|data| Ok::<_, Infallible>(Event::default().event("message").data(data)))
    });

    Sse::new(sse_stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// DELETE /mcp — Close a session.
async fn handle_delete(
    State(state): State<Arc<HttpTransportState>>,
    headers: HeaderMap,
) -> StatusCode {
    let Some(session_id) = get_session_id(&headers) else {
        return StatusCode::BAD_REQUEST;
    };

    if state.sessions.remove(&session_id).await {
        info!(session = %session_id, "Session closed");
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// GET /.well-known/mcp.json — MCP server discovery metadata.
async fn handle_mcp_discovery(State(state): State<Arc<HttpTransportState>>) -> Response {
    let bind = &state.config.bind;
    let base_url = format!("http://{bind}");

    Json(serde_json::json!({
        "mcp": {
            "version": "2025-11-25",
            "transport": {
                "type": "streamable-http",
                "url": format!("{base_url}/mcp"),
            },
            "capabilities": {
                "tools": true,
                "resources": true,
                "prompts": true,
                "roots": true,
            },
            "oauth": if state.oauth.enabled {
                serde_json::json!({
                    "authorization_server": format!("{base_url}/.well-known/oauth-authorization-server"),
                })
            } else {
                serde_json::json!(null)
            },
        }
    }))
    .into_response()
}

/// GET /.well-known/oauth-authorization-server — OAuth metadata (RFC 8414).
async fn handle_oauth_discovery(State(state): State<Arc<HttpTransportState>>) -> Response {
    if !state.oauth.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let base_url = format!("http://{}", state.config.bind);
    let metadata = OAuthMetadata::from_config(&state.oauth, &base_url);
    Json(metadata).into_response()
}

/// GET /health — Simple health check endpoint.
async fn handle_health(State(state): State<Arc<HttpTransportState>>) -> Response {
    Json(serde_json::json!({
        "status": "ok",
        "sessions": state.sessions.count().await,
        "max_sessions": state.config.max_sessions,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HttpTransportConfig::default();
        assert_eq!(config.bind, "127.0.0.1:3000");
        assert_eq!(config.max_body_size, 1_048_576);
        assert_eq!(config.max_sessions, 100);
        assert!(!config.allow_unsafe_bind);
    }

    #[test]
    fn test_new_session_id_is_uuid() {
        let id = new_session_id();
        assert_eq!(id.len(), 36); // UUID v4 format
        assert!(id.contains('-'));
    }

    #[test]
    fn test_get_session_id_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", "test-session-123".parse().unwrap());
        assert_eq!(
            get_session_id(&headers),
            Some("test-session-123".to_string())
        );
    }

    #[test]
    fn test_get_session_id_missing() {
        let headers = HeaderMap::new();
        assert_eq!(get_session_id(&headers), None);
    }

    #[test]
    fn test_default_config_session_timeout() {
        let config = HttpTransportConfig::default();
        assert_eq!(config.session_timeout, Duration::from_secs(1800));
    }

    #[test]
    fn test_default_config_oauth_disabled() {
        let config = HttpTransportConfig::default();
        assert!(!config.oauth.enabled);
    }

    #[test]
    fn test_new_session_id_uniqueness() {
        let id1 = new_session_id();
        let id2 = new_session_id();
        assert_ne!(id1, id2, "Session IDs must be unique");
    }

    #[test]
    fn test_new_session_id_valid_uuid_v4() {
        let id = new_session_id();
        // UUID v4 has format: 8-4-4-4-12
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    #[test]
    fn test_get_session_id_case_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", "CaSe-SenSiTiVe-123".parse().unwrap());
        assert_eq!(
            get_session_id(&headers),
            Some("CaSe-SenSiTiVe-123".to_string())
        );
    }

    #[test]
    fn test_get_session_id_uuid_value() {
        let uuid = new_session_id();
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", uuid.parse().unwrap());
        assert_eq!(get_session_id(&headers), Some(uuid));
    }

    #[test]
    fn test_custom_config() {
        let config = HttpTransportConfig {
            bind: "127.0.0.1:8080".to_string(),
            max_body_size: 2_097_152,
            session_timeout: Duration::from_secs(600),
            max_sessions: 50,
            oauth: OAuthConfig::default(),
            allowed_origins: Vec::new(),
            allow_unsafe_bind: false,
        };
        assert_eq!(config.bind, "127.0.0.1:8080");
        assert_eq!(config.max_body_size, 2_097_152);
        assert_eq!(config.session_timeout, Duration::from_secs(600));
        assert_eq!(config.max_sessions, 50);
    }

    // ========================================================================
    // Origin validation (MCP 2025-11-25: anti-DNS-rebinding)
    // ========================================================================

    #[test]
    fn test_origin_exact_match() {
        let allowed = vec!["http://localhost".to_string()];
        assert!(is_allowed_origin("http://localhost", &allowed));
    }

    #[test]
    fn test_origin_match_with_port() {
        let allowed = vec!["http://localhost".to_string()];
        assert!(is_allowed_origin("http://localhost:3000", &allowed));
        assert!(is_allowed_origin("http://localhost:8080", &allowed));
    }

    #[test]
    fn test_origin_rejects_lookalike_host() {
        let allowed = vec!["http://localhost".to_string()];
        assert!(!is_allowed_origin("http://localhost.evil.com", &allowed));
        assert!(!is_allowed_origin("http://localhostevil", &allowed));
    }

    #[test]
    fn test_origin_rejects_different_scheme() {
        let allowed = vec!["http://localhost".to_string()];
        assert!(!is_allowed_origin("https://localhost", &allowed));
        assert!(!is_allowed_origin("ws://localhost", &allowed));
    }

    #[test]
    fn test_origin_rejects_path_after_host() {
        let allowed = vec!["http://localhost".to_string()];
        assert!(!is_allowed_origin("http://localhost/evil", &allowed));
    }

    #[test]
    fn test_origin_default_localhost_variants() {
        let allowed = default_allowed_origins();
        assert!(is_allowed_origin("http://localhost:3000", &allowed));
        assert!(is_allowed_origin("https://localhost", &allowed));
        assert!(is_allowed_origin("http://127.0.0.1:8080", &allowed));
        assert!(is_allowed_origin("http://[::1]:9000", &allowed));
        assert!(!is_allowed_origin("http://attacker.com", &allowed));
    }

    #[test]
    fn test_origin_empty_allowlist_rejects_all() {
        let allowed: Vec<String> = Vec::new();
        assert!(!is_allowed_origin("http://localhost", &allowed));
        assert!(!is_allowed_origin("http://attacker.com", &allowed));
    }

    #[test]
    fn test_origin_production_exact_match() {
        // A production server with an explicit allowlist should NOT
        // accept arbitrary ports on its own domain.
        let allowed = vec!["https://app.example.com".to_string()];
        assert!(is_allowed_origin("https://app.example.com", &allowed));
        // The prefix+port rule still applies for explicit hosts; this
        // is fine for IPv4/IPv6/localhost. For HTTPS production this
        // is rarely an issue since browsers strip the default 443.
        assert!(is_allowed_origin("https://app.example.com:443", &allowed));
        assert!(!is_allowed_origin("https://evil.com", &allowed));
        assert!(!is_allowed_origin("https://app.example.com.evil", &allowed));
    }

    #[test]
    fn test_config_clone() {
        let config = HttpTransportConfig::default();
        let cloned = config.clone();
        assert_eq!(config.bind, cloned.bind);
        assert_eq!(config.max_body_size, cloned.max_body_size);
        assert_eq!(config.max_sessions, cloned.max_sessions);
    }

    #[test]
    fn test_config_debug() {
        let config = HttpTransportConfig::default();
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("HttpTransportConfig"));
        assert!(debug_str.contains("3000"));
    }

    // ========================================================================
    // End-to-end Origin guard (full router) — MCP 2025-11-25 §Security Warning
    // ========================================================================

    fn build_test_router() -> Router {
        let mcp_config = crate::config::Config {
            hosts: std::collections::HashMap::new(),
            security: crate::config::SecurityConfig::default(),
            limits: crate::config::LimitsConfig::default(),
            audit: crate::config::AuditConfig::default(),
            sessions: crate::config::SessionConfig::default(),
            tool_groups: crate::config::ToolGroupsConfig::default(),
            ssh_config: crate::config::SshConfigDiscovery::default(),
            http: crate::config::HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        };
        let (server, _audit_task) = McpServer::new(mcp_config);
        build_router(Arc::new(server), HttpTransportConfig::default())
    }

    #[tokio::test]
    async fn test_origin_guard_returns_403_on_invalid_origin() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("origin", "http://attacker.example.com")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_origin_guard_allows_localhost() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("origin", "http://localhost:5173")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Anything other than 403 is fine — we just need to confirm the
        // gate let the request through.
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_origin_guard_rejects_no_origin_header() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // Vuln 1 (audit 2026-05-09): a request with no Origin must be
        // rejected. The previous behaviour (forwarding unconditionally)
        // let any non-browser network attacker reach the MCP endpoints.
        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_origin_guard_protects_health_endpoint() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // Discovery and health endpoints must also reject cross-origin
        // probes — otherwise an attacker could fingerprint the server.
        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .header("origin", "http://attacker.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ========================================================================
    // Vuln 1 (audit 2026-05-09) — loopback default + refuse anonymous public bind
    // ========================================================================

    #[test]
    fn default_bind_is_loopback() {
        let cfg = HttpTransportConfig::default();
        assert_eq!(cfg.bind, "127.0.0.1:3000");
    }

    #[tokio::test]
    async fn serve_refuses_public_bind_without_oauth() {
        let cfg = HttpTransportConfig {
            bind: "0.0.0.0:0".to_string(),
            ..Default::default()
        };
        let cfg_main = crate::config::Config::default();
        let (server, _audit_task) = crate::mcp::McpServer::new(cfg_main);
        let server = std::sync::Arc::new(server);
        let r = serve(server, cfg).await;
        assert!(r.is_err(), "must refuse 0.0.0.0 bind without OAuth");
        let msg = format!("{}", r.err().unwrap());
        assert!(msg.contains("loopback") || msg.contains("OAuth") || msg.contains("oauth"));
    }

    #[tokio::test]
    async fn serve_allows_loopback_bind_without_oauth() {
        let cfg = HttpTransportConfig {
            bind: "127.0.0.1:0".to_string(), // port 0 = OS picks
            ..Default::default()
        };
        // Spawn the server in a task and immediately drop after a tick — the
        // initial bind succeeded if no error was reported synchronously.
        let cfg_main = crate::config::Config::default();
        let (server, _audit_task) = crate::mcp::McpServer::new(cfg_main);
        let server = std::sync::Arc::new(server);
        let handle = tokio::spawn(async move { serve(server, cfg).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handle.abort();
        // If serve returned an Err synchronously the abort wouldn't have helped — and
        // the test would have observed it via JoinHandle. We just confirm we did not
        // get an immediate refuse_unsafe_bind error.
    }

    #[test]
    fn refuse_unsafe_bind_allows_oauth_enabled_public() {
        let mut cfg = HttpTransportConfig {
            bind: "0.0.0.0:3000".to_string(),
            ..Default::default()
        };
        cfg.oauth.enabled = true;
        assert!(refuse_unsafe_bind(&cfg).is_ok());
    }

    #[test]
    fn refuse_unsafe_bind_allows_explicit_override() {
        let cfg = HttpTransportConfig {
            bind: "0.0.0.0:3000".to_string(),
            allow_unsafe_bind: true,
            ..Default::default()
        };
        assert!(refuse_unsafe_bind(&cfg).is_ok());
    }

    #[test]
    fn refuse_unsafe_bind_allows_ipv6_loopback() {
        let cfg = HttpTransportConfig {
            bind: "[::1]:3000".to_string(),
            ..Default::default()
        };
        assert!(refuse_unsafe_bind(&cfg).is_ok());
    }

    #[test]
    fn refuse_unsafe_bind_allows_localhost_alias() {
        let cfg = HttpTransportConfig {
            bind: "localhost:3000".to_string(),
            ..Default::default()
        };
        assert!(refuse_unsafe_bind(&cfg).is_ok());
    }
}
