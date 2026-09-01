//! Streamable HTTP Transport (MCP 2026-07-28)
//!
//! `POST /mcp` is the whole transport. A request answers with
//! `application/json`, except `subscriptions/listen`, which answers with a
//! long-lived `text/event-stream` on its own response body.
//!
//! THERE IS NO SESSION. 2026-07-28 made MCP stateless: every request carries
//! its protocol version, client identity and client capabilities in `_meta`,
//! and the spec forbids inferring them from earlier requests. So there is
//! nothing for an `Mcp-Session-Id` to key, and `GET`/`DELETE` on `/mcp`
//! answer `405`.
//!
//! What the GET endpoint used to do — carry server-to-client notifications —
//! is now `subscriptions/listen`'s job, per the changelog: *"Replace the HTTP
//! GET endpoint and `resources/subscribe`/`resources/unsubscribe` with
//! `subscriptions/listen`."*

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

use super::oauth::{OAuthConfig, OAuthMetadata, OAuthValidator, ProtectedResourceMetadata};

use crate::mcp::protocol::{
    JsonRpcError, JsonRpcResponse, PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, WriterMessage,
};
use crate::mcp::request_meta::missing_required_envelope_field;
use crate::mcp::server::McpServer;
use crate::mcp::session_context::SessionContext;

/// Default allowlist for the `Origin` header — localhost variants only.
///
/// 2026-07-28, Streamable HTTP "Security & Endpoint": *"Servers **MUST**
/// validate the `Origin` header on all incoming connections to prevent DNS
/// rebinding attacks."* Production deployments should override this list to
/// include their public origin.
///
/// The requirement was previously cited here as "MCP 2025-11-25". It is
/// current, not inherited: the text above is on the 2026-07-28 transport page.
/// A correct rule under a stale citation reads like leftover Legacy support,
/// which is the one thing this branch must not look like.
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
            oauth: OAuthConfig::default(),
            allowed_origins: default_allowed_origins(),
            allow_unsafe_bind: false,
        }
    }
}

/// Shared state for the HTTP transport.
pub struct HttpTransportState {
    config: HttpTransportConfig,
    /// The MCP server processes requests from any session.
    server: Arc<McpServer>,
    /// OAuth configuration.
    oauth: Arc<OAuthConfig>,
}

/// Anti-DNS-rebinding gate (2026-07-28 §"Streamable HTTP / Security & Endpoint").
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

/// A JSON-RPC error body carried by HTTP `400`.
///
/// Modelled on [`forbidden`], which was the only place in this file pairing a
/// JSON-RPC error with a non-200 status. The body is built through
/// `JsonRpcResponse::error` rather than a hand-written literal so it is
/// byte-identical to what the stdio transport returns for the same refusal —
/// two hand-written shapes would drift, and only one transport's tests would
/// notice.
///
/// Contrast `validate_protocol_version`'s 400, which answers a bare string a
/// JSON-RPC client cannot parse. That is inherited and is Task 66's to
/// reconcile.
fn bad_request(id: Option<Value>, error: JsonRpcError) -> Response {
    let resp = JsonRpcResponse::error(id, error);
    (StatusCode::BAD_REQUEST, Json(resp)).into_response()
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
    build_router_inner(server, config, None)
}

/// Build the axum Router with a pre-built [`OAuthValidator`] installed
/// as a request extension. Used by [`serve`] after the validator has
/// been constructed at boot via [`super::oauth::build_validator_from_runtime`].
pub fn build_router_with_validator(
    server: Arc<McpServer>,
    config: HttpTransportConfig,
    validator: &Arc<OAuthValidator>,
) -> Router {
    build_router_inner(server, config, Some(validator))
}

/// RETIRES `build_router_with_store`, whose whole reason for existing was a
/// caller-provided session store.
///
/// Its doc comment said it was there "for future shared-store deployments
/// (Redis, Valkey, …) once the stateless-transport spec lands". That spec has
/// landed, and it did the opposite of what the comment anticipated: it removed
/// sessions rather than distributing them, so the abstraction has nothing left
/// to abstract.
fn build_router_inner(
    server: Arc<McpServer>,
    config: HttpTransportConfig,
    validator: Option<&Arc<OAuthValidator>>,
) -> Router {
    // The 401 challenge has to name an absolute URL, and only this function
    // knows the address this process is bound to. Runtime-populated rather
    // than a YAML key, for the same reason `static_keys` is.
    let mut oauth_runtime = config.oauth.clone();
    if oauth_runtime.resource_metadata_url.is_empty() {
        oauth_runtime.resource_metadata_url = format!(
            "http://{}/.well-known/oauth-protected-resource",
            config.bind
        );
    }
    let oauth_config = Arc::new(oauth_runtime);

    let state = Arc::new(HttpTransportState {
        config,
        server,
        oauth: Arc::clone(&oauth_config),
    });

    let mut router = Router::new()
        .route("/mcp", post(handle_post))
        .route("/mcp", get(mcp_method_not_allowed))
        .route("/mcp", delete(mcp_method_not_allowed));

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
            "/.well-known/oauth-protected-resource",
            get(handle_protected_resource_metadata),
        )
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
            // KEPT although this revision has no sessions, and kept
            // deliberately. The spec's instruction for a header from an older
            // client is *"An `Mcp-Session-Id` header on a request: ignore it,
            // and do not mint or echo session IDs"* — ignore, not refuse. CORS
            // `allow_headers` gates whether a browser may SEND a header at
            // all, so dropping it here would turn "ignore it" into "block the
            // whole request at preflight" for exactly the legacy browser
            // clients the instruction is about.
            axum::http::HeaderName::from_static("mcp-session-id"),
            axum::http::HeaderName::from_static("mcp-protocol-version"),
            // Required by Server Validation, so they must survive
            // preflight — a header the browser strips is a header the
            // server then refuses the request for.
            axum::http::HeaderName::from_static("mcp-method"),
            axum::http::HeaderName::from_static("mcp-name"),
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
///
/// `audit_task` is the writer half returned by [`McpServer::new`] and is
/// spawned here, mirroring [`McpServer::serve`]. It is a parameter rather
/// than something the caller is trusted to spawn because the caller used to
/// bind it to `_audit_task` and drop it on the spot: the channel then closed
/// and every event was discarded by `let _ = send(...)`, leaving `audit.log`
/// created-but-empty on the one transport whose selling point is the audit
/// trail. Pass `None` only when auditing is genuinely disabled.
pub async fn serve(
    server: Arc<McpServer>,
    config: HttpTransportConfig,
    audit_task: Option<crate::security::AuditWriterTask>,
) -> crate::error::Result<()> {
    refuse_unsafe_bind(&config)?;

    if let Some(task) = audit_task {
        tokio::spawn(task.run());
    }

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

/// Methods that must also carry `Mcp-Name`, and where its value comes from.
///
/// The spec's table is exact: `Mcp-Name` mirrors `params.name` or
/// `params.uri`, and is required for these three methods only. Anything else
/// carrying an `Mcp-Name` is not an error — the table says which methods
/// REQUIRE it, not which may send it.
const MCP_NAME_METHODS: &[(&str, &str)] = &[
    ("tools/call", "name"),
    ("resources/read", "uri"),
    ("prompts/get", "name"),
];

/// Wrapper marking a header value as Base64 rather than literal.
///
/// *"The prefix `=?base64?` and suffix `?=` indicate that the value is
/// Base64-encoded. These markers are case-sensitive and **MUST** appear exactly
/// as shown (lowercase)."*
const B64_SENTINEL_PREFIX: &str = "=?base64?";
const B64_SENTINEL_SUFFIX: &str = "?=";

/// Decode a header value that may carry the Base64 sentinel.
///
/// Required, not decorative: *"servers **MUST** decode an encoded `Mcp-Name` or
/// `Mcp-Param-{Name}` value before comparing it to the corresponding request
/// body value during Server Validation."*
///
/// Without it every conforming request whose name or URI is not plain-ASCII-safe
/// is rejected `-32020` for a mismatch that does not exist. That is not a corner
/// case here: `Mcp-Name` mirrors `params.uri` on `resources/read`, and this
/// server serves `file://` and `log://` URIs off remote hosts, where a
/// non-ASCII path is ordinary. A client is REQUIRED to encode in that case —
/// *"clients **MUST** use Base64 encoding of the UTF-8 representation"* — so
/// the better a client conformed, the more reliably it was refused.
///
/// STANDARD alphabet with padding, not URL-safe: the spec's own examples
/// contain `/` (`PT9iYXNlNjQ/bGl0ZXJhbD89`) and `=` padding
/// (`SGVsbG8sIOS4lueVjA==`).
///
/// A value that does not carry the wrapper is returned untouched. Clients
/// resolve the ambiguity from the other side — *"clients **MUST** also
/// Base64-encode any plain-ASCII value that matches the sentinel pattern"* — so
/// an unwrapped value is always literal.
fn decode_header_sentinel(value: &str) -> Result<std::borrow::Cow<'_, str>, &'static str> {
    use base64::Engine as _;

    let Some(encoded) = value
        .strip_prefix(B64_SENTINEL_PREFIX)
        .and_then(|rest| rest.strip_suffix(B64_SENTINEL_SUFFIX))
    else {
        return Ok(std::borrow::Cow::Borrowed(value));
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "not valid Base64")?;
    String::from_utf8(bytes)
        .map(std::borrow::Cow::Owned)
        .map_err(|_| "not valid UTF-8")
}

/// Server Validation for MCP 2026-07-28 Streamable HTTP.
///
/// The spec makes three request headers REQUIRED on a POST — *"Every POST
/// request to the MCP endpoint **MUST** include an `MCP-Protocol-Version`
/// header"*, and for the other two, *"These headers are **REQUIRED** for
/// compliance"*:
///
/// | Header | Source field | Required for |
/// |---|---|---|
/// | `MCP-Protocol-Version` | — | every POST |
/// | `Mcp-Method` | `method` | all requests |
/// | `Mcp-Name` | `params.name` or `params.uri` | `tools/call`, `resources/read`, `prompts/get` |
///
/// and pins the refusal: *"When rejecting a request due to header validation
/// failure, servers **MUST** return HTTP status `400 Bad Request` and
/// **MUST** include a JSON-RPC error response"* carrying `-32020`.
///
/// BOTH failure kinds are covered, and reading only the first sentence of the
/// spec's section would miss one. Its opening line covers mismatch only —
/// *"reject requests where the values specified in the headers do not match
/// the corresponding values in the request body"* — and it is the
/// failure-conditions list that adds *"A required standard header
/// (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`) is missing"*. Absence is
/// the entire Legacy-`initialize` case, so missing that clause would leave
/// the case this function exists for unhandled.
///
/// WHAT REPLACED WHAT: this supersedes a `validate_protocol_version` that
/// ACCEPTED an absent header, assuming `2025-03-26` for backwards
/// compatibility, and answered failures with a bare string body no JSON-RPC
/// client could parse. Both behaviours were correct for 2025-11-25 and are
/// non-conformant for 2026-07-28 — the assumption in particular let a Legacy
/// client through the door it is now refused at.
///
/// `Accept` IS NOT CHECKED, AND THAT IS CORRECT — recorded because the
/// omission looks like one. Sending Messages does say *"The client MUST
/// include an `Accept` header listing both `application/json` and
/// `text/event-stream`"*, and reading only that line makes a missing `Accept`
/// look like a request this server should refuse. It is a CLIENT MUST with no
/// server-side counterpart: Server Validation enumerates exactly three
/// conditions — a required standard header (`MCP-Protocol-Version`,
/// `Mcp-Method`, `Mcp-Name`) missing, a header value not matching the body, a
/// header value containing invalid characters — and `Accept` is in none of
/// them, nor in the "required standard header" list that clause names.
/// Rejecting on it would invent a `-32020` the closed-world rule for
/// `-32020..-32099` does not allow this server to mint.
///
/// ORDERING: header validation runs BEFORE version-support checking. The two
/// MUSTs can fire on the same request — a Legacy client at 2025-06-18 or
/// later DOES send `MCP-Protocol-Version`, so its `initialize` POST is both
/// missing `Mcp-Method` and naming an unsupported version — and the spec
/// states no precedence between them. The Compatibility Matrix resolves this
/// exact row in favour of server validation: *"HTTP: the request is missing
/// the required headers and is rejected per server validation with `400 Bad
/// Request`"*.
fn check_modern_headers(headers: &HeaderMap, body: &Value) -> Result<(), JsonRpcError> {
    let header = |name: &str| -> Option<&str> { headers.get(name).and_then(|v| v.to_str().ok()) };

    let Some(version) = header("mcp-protocol-version") else {
        return Err(JsonRpcError::header_mismatch(
            "missing required header `MCP-Protocol-Version`",
        ));
    };

    // An array body is refused before this function is reached — 2026-07-28
    // has no JSON-RPC batching and the POST body MUST be a single request or
    // notification. The guard stays so the function is TOTAL: it is called
    // directly by unit tests, and a header check that panicked or silently
    // passed on a shape its caller happens to filter would be a trap for the
    // next caller.
    if !body.is_array() {
        let Some(method) = header("mcp-method") else {
            return Err(JsonRpcError::header_mismatch(
                "missing required header `Mcp-Method`",
            ));
        };
        let body_method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if method != body_method {
            return Err(JsonRpcError::header_mismatch(format!(
                "`Mcp-Method: {method}` does not match the body's method `{body_method}`"
            )));
        }

        if let Some((_, field)) = MCP_NAME_METHODS.iter().find(|(m, _)| *m == body_method) {
            let Some(name) = header("mcp-name") else {
                return Err(JsonRpcError::header_mismatch(format!(
                    "missing required header `Mcp-Name` for `{body_method}`"
                )));
            };
            let body_name = body
                .get("params")
                .and_then(|p| p.get(field))
                .and_then(Value::as_str)
                .unwrap_or_default();
            // Decoded BEFORE comparison, because that is the order the spec
            // states. Comparing the wrapper against the body value would
            // refuse every correctly-encoded request.
            let name = decode_header_sentinel(name).map_err(|why| {
                JsonRpcError::header_mismatch(format!(
                    "`Mcp-Name` carries the Base64 sentinel but its payload is {why}"
                ))
            })?;
            if name != body_name {
                return Err(JsonRpcError::header_mismatch(format!(
                    "`Mcp-Name: {name}` does not match the body's `params.{field}` \
                     `{body_name}`"
                )));
            }
        }
    }

    // The header and the envelope are a header/body PAIR, so a disagreement
    // between them is a mismatch under the same rule as `Mcp-Method`:
    // *"reject requests where the values specified in the headers do not
    // match the corresponding values in the request body"*. The spec's table
    // names `method` and `params.name`/`params.uri` as source fields and does
    // not list the revision, so this is the rule read on its own terms rather
    // than a row quoted from the table — and it is checked before support,
    // because "your two copies disagree" is a different and more actionable
    // answer than "I do not speak the one I happened to read".
    if let Some(declared) = body
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get("io.modelcontextprotocol/protocolVersion"))
        .and_then(Value::as_str)
        && declared != version
    {
        return Err(JsonRpcError::header_mismatch(format!(
            "`MCP-Protocol-Version: {version}` does not match the body's \
             `_meta` protocolVersion `{declared}`"
        )));
    }

    // Version support is checked LAST, per the ordering note above. Over HTTP
    // the spec pins this one too: *"If the server does not implement the
    // requested protocol version ... it **MUST** respond with `400 Bad
    // Request` and an `UnsupportedProtocolVersionError` listing its supported
    // versions."*
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&version) {
        return Err(JsonRpcError::unsupported_protocol_version(version));
    }

    Ok(())
}

/// `GET` and `DELETE` on `/mcp` — gone, and answered as gone.
///
/// `GET` used to serve the SSE notification stream and `DELETE` used to close
/// a session. 2026-07-28 removed both: notifications moved onto
/// `subscriptions/listen`'s own POST response, and there is no session to
/// close.
///
/// `405` with an `Allow` header rather than `404`, because the path exists and
/// the METHOD does not — a `404` would tell a client the endpoint is absent
/// and send it looking for another one.
async fn mcp_method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(axum::http::header::ALLOW, "POST")],
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32600,
                "message": "MCP 2026-07-28 has no GET or DELETE on /mcp: \
                            notifications arrive on the subscriptions/listen \
                            POST response, and there is no session to close"
            }
        })),
    )
        .into_response()
}

/// POST /mcp — Handle JSON-RPC requests.
#[allow(clippy::too_many_lines)]
async fn handle_post(
    State(state): State<Arc<HttpTransportState>>,
    headers: HeaderMap,
    // Raw text, not `Json<Value>`. Going through `serde_json::Value` first
    // silently keeps the LAST of any duplicate member, so
    // `{"method":"tools/list","method":"tools/call"}` reached this handler as
    // a plain `tools/call` — while stdio and the daemon socket, which
    // deserialise straight into `JsonRpcMessage`, refused the same bytes with
    // "duplicate field `method`". That is the array divergence again in a new
    // costume, and it is worse: anything reading the first member (a proxy, an
    // audit log, a policy layer) disagreed with what the server executed. The
    // body is now read as bytes and handed to the SAME `parse_incoming` the
    // other two transports use, so the answer cannot depend on which door the
    // client knocked at.
    raw_body: String,
) -> Response {
    // `Json` used to enforce this; reading the body as text does not, so the
    // check is explicit rather than lost.
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("application/json")
    {
        warn!(%content_type, "Rejecting a POST that is not application/json");
        return bad_request(
            None,
            JsonRpcError::invalid_request(
                "the body of an MCP POST must be sent as `Content-Type: application/json`",
            ),
        );
    }

    // Parsed once for inspection only — the array guard, the header check and
    // the `id` echoed on failure. The message the server acts on comes from
    // `parse_incoming` below, reading the same raw text.
    let body: Value = match serde_json::from_str(&raw_body) {
        Ok(value) => value,
        Err(e) => {
            return bad_request(
                None,
                JsonRpcError::parse_error(format!("Invalid JSON: {e}")),
            );
        }
    };
    // JSON-RPC batching was removed in 2025-06-18 and 2026-07-28 does not
    // bring it back: `JSONRPCMessage` is `JSONRPCRequest | JSONRPCNotification
    // | JSONRPCResponse`, three object types and no array form, and the word
    // "batch" does not occur anywhere in the published schema. Streamable HTTP
    // then says it outright: *"The body of the HTTP POST **MUST** be a single
    // JSON-RPC _request_ or _notification_."*
    //
    // The CODE is our choice, and this says so rather than implying the spec
    // settled it: the spec states the client-side MUST but enumerates no
    // server-side rejection procedure for an array body. `-32600 Invalid
    // Request` is the JSON-RPC answer for a body that is not a valid Request,
    // and `400` follows the same reasoning as every other malformed-request
    // refusal on this transport.
    //
    // SCOPE: this refusal was HTTP-only for one release, and the divergence
    // it created is now closed. `serve_session`'s batch arm accepted arrays
    // on stdio and the daemon socket, on the reasoning that the quoted MUST
    // is written for the HTTP POST body. That reasoning held for the quote
    // and not for the schema: `JSONRPCMessage` has no array form on ANY
    // transport, so the answer must not depend on which door the client
    // knocked at. `McpServer::parse_incoming` now refuses arrays with the
    // same `-32600` for the other two.
    if body.is_array() {
        warn!("Rejecting a JSON array body: 2026-07-28 has no JSON-RPC batching");
        return bad_request(
            None,
            JsonRpcError::invalid_request(
                "the body of an MCP POST must be a single JSON-RPC request or \
                 notification; JSON-RPC batching was removed in revision 2025-06-18",
            ),
        );
    }

    // Server Validation, before anything else touches the request. The body
    // is needed to compare headers against it, so this cannot be a
    // header-only middleware — but it IS still before dispatch, and before
    // the body is deserialised into typed messages.
    if let Err(e) = check_modern_headers(&headers, &body) {
        warn!(code = e.code, message = %e.message, "Header validation failed");
        return bad_request(body.get("id").cloned(), e);
    }

    // Parse the request. The array case is already gone: the guard above
    // returns before this point, so there is exactly one shape left to
    // deserialise. Until 3.0.0 an `if body.is_array()` branch stood here
    // building an `IncomingMessage::Batch` — dead code, unreachable behind
    // that same guard, and the sort that reads as a supported feature to
    // anyone scanning the file.
    // The same parser stdio and the daemon socket use, over the same raw
    // bytes — not `from_value` over a `Value` that has already dropped
    // duplicate members. One parser, one verdict, whatever the transport.
    let msg = match crate::mcp::server::McpServer::parse_incoming(&raw_body) {
        Ok(msg) => msg,
        Err(e) => {
            let resp = JsonRpcResponse::error(None, e);
            return Json(resp).into_response();
        }
    };

    if msg.method.is_none() {
        return StatusCode::NO_CONTENT.into_response();
    }
    // JSON-RPC 2.0 §4.1: a Notification is a Request with no `id`. Gate on
    // that, not on the method name — the stdio transport's
    // `McpServer::route_incoming_message` gates identically. Still dispatch
    // through `handle_request`, even though `handle_request_with_cancel` has
    // no arm for any `notifications/*` method today: it falls through to
    // `method_not_found`, which is discarded below just like any real result
    // would be.
    let is_notification = msg.id.is_none();

    // C3: the SAME predicate the dispatch chokepoint uses, answered here with
    // a real HTTP status. `handle_request` produces the `-32602` body on its
    // own; what it cannot do is set the status, because it has no idea it is
    // being called over HTTP.
    //
    // Before dispatch, so a malformed request does no work — the same
    // placement as `validate_protocol_version` at the top of this function.
    if let Some(detail) = missing_required_envelope_field(
        msg.method.as_deref().unwrap_or_default(),
        msg.id.is_some(),
        msg.params.as_ref(),
    ) {
        return bad_request(msg.id.clone(), JsonRpcError::invalid_params(detail));
    }

    let request = crate::mcp::protocol::JsonRpcRequest {
        jsonrpc: msg.jsonrpc,
        id: msg.id,
        method: msg.method.unwrap_or_default(),
        params: msg.params,
    };

    // The one method whose answer is a STREAM rather than a value. Routed
    // before the generic dispatch because everything below assumes a single
    // completed response.
    if request.method == "subscriptions/listen" {
        return serve_listen_stream(&state, request).await;
    }

    let resp = state.server.handle_request(request).await;
    if is_notification {
        // §5: "the receiver must not send a response to a notification". The
        // Streamable HTTP transport spec is explicit: a POST body consisting
        // solely of notifications (or responses) MUST get HTTP 202 Accepted
        // with no body.
        return StatusCode::ACCEPTED.into_response();
    }

    // "If the server does not implement the requested RPC method, it MUST
    // respond with `404 Not Found` and a JSON-RPC error with code `-32601`
    // (`Method not found`)."
    //
    // The BODY was already right; only the status was wrong, and the status is
    // the half that carries information this server cannot otherwise send.
    // The spec says why in the same paragraph: "The JSON-RPC error body
    // distinguishes this case from a `404` returned by a legacy HTTP+SSE
    // server that does not host the modern MCP endpoint." The two halves are a
    // pair — `404` says "not here", the body says "this IS the endpoint, that
    // method is not". Answering `200` broke the client's side of that
    // handshake: Backward Compatibility has a dual-era client fall back to
    // `initialize` on `400`/`404`/`405` unless the body is a recognised modern
    // error, and a `200` is not one of the statuses it inspects at all.
    //
    // Scoped to `-32601` on the nose. Every other JSON-RPC error is a fault in
    // a method this server DOES implement, and those stay `200` — remapping
    // them would tell a client the endpoint is missing whenever a tool
    // rejected its arguments.
    let is_method_not_found = resp.error.as_ref().is_some_and(|e| e.code == -32601);
    if is_method_not_found {
        return (StatusCode::NOT_FOUND, Json(resp)).into_response();
    }

    Json(resp).into_response()
}

/// Removes this stream's subscriptions when the stream is dropped.
///
/// It MUST be owned by the stream, not by the handler that builds it. A guard
/// held in a local would run its `Drop` the moment the handler returns —
/// which is immediately, since the handler returns the stream — and the
/// subscription would be gone before the first notification.
///
/// Dropping happens on every way out: the client closing the connection,
/// hyper dropping the body, or the response being cancelled. That is the
/// whole reason this is RAII rather than an explicit teardown call.
struct SubscriptionStreamGuard {
    server: Arc<McpServer>,
    tx: mpsc::Sender<WriterMessage>,
}

impl Drop for SubscriptionStreamGuard {
    fn drop(&mut self) {
        let removed = self.server.remove_subscriptions_for_tx(&self.tx);
        if removed > 0 {
            info!(
                removed,
                "subscriptions/listen stream closed, subscriptions dropped"
            );
        }
    }
}

/// Serve an accepted `subscriptions/listen` as the POST's own response body.
///
/// 2026-07-28 replaced the standalone `GET` endpoint with this: *"Replace the
/// HTTP GET endpoint and `resources/subscribe`/`resources/unsubscribe` with
/// `subscriptions/listen`: a single long-lived POST-response stream for
/// opted-in server-to-client change notifications."*
///
/// The content type is forced rather than quoted. The normative rule is a
/// disjunction for any request — the server *"**MUST** return either
/// `Content-Type: application/json` ... or `Content-Type: text/event-stream`"*
/// — and the listen-specific text then states as fact that *"The server's
/// response is itself an SSE stream that stays open"*. A single JSON object
/// cannot stay open, so SSE is the only member of that disjunction which can
/// satisfy it; there is no sentence saying "MUST be text/event-stream", and
/// this comment does not invent one.
///
/// A REJECTED listen answers normally, as JSON. It has no stream to hold open
/// and pretending otherwise would leave the client waiting on a body that
/// will never carry anything.
///
/// The request id is deliberately NOT answered on acceptance: it is the
/// subscription id, and it stays open for the life of the stream. The first
/// thing the client sees is the acknowledgement NOTIFICATION, which the
/// dispatcher has already written into the channel by the time this returns.
async fn serve_listen_stream(
    state: &Arc<HttpTransportState>,
    request: crate::mcp::protocol::JsonRpcRequest,
) -> Response {
    let (tx, rx) = mpsc::channel::<WriterMessage>(100);
    let session = SessionContext::new(tx.clone());

    let outcome = state
        .server
        .handle_request_with_cancel(request, None, Some(&session))
        .await;

    if let Some(response) = outcome {
        // Refused — answer it and let the channel die with this scope.
        return Json(response).into_response();
    }

    let guard = SubscriptionStreamGuard {
        server: Arc::clone(&state.server),
        tx,
    };

    let stream = tokio_stream::StreamExt::filter_map(ReceiverStream::new(rx), move |msg| {
        // The guard is captured by the closure, so it lives exactly as long as
        // the stream does. Touching it here is what stops it being optimised
        // into a value dropped at construction.
        let _guard = &guard;
        let json_str = match &msg {
            WriterMessage::Response(r) => serde_json::to_string(&**r).ok(),
            WriterMessage::Notification(n) => serde_json::to_string(n).ok(),
        };
        json_str.map(|data| Ok::<_, Infallible>(Event::default().event("message").data(data)))
    });

    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response();

    // "When initiating an SSE stream, servers SHOULD include the
    // `X-Accel-Buffering: no` header in the HTTP response. This instructs
    // reverse proxies (such as nginx) to disable response buffering."
    //
    // It matters most for exactly this stream. A `subscriptions/listen` is
    // quiet by design — it exists to carry an event that has not happened yet
    // — and a buffering proxy will hold each notification until it has enough
    // bytes to flush. The symptom is not a broken connection but a stream that
    // silently arrives minutes late, which reads as "the server never sent
    // it".
    //
    // `KeepAlive::default()` above covers the other half the transport page
    // asks for: the periodic SSE comment line that stops an intermediary or an
    // idle timeout from closing a quiet stream.
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-accel-buffering"),
        axum::http::HeaderValue::from_static("no"),
    );
    response
}

/// GET /.well-known/mcp.json — MCP server discovery metadata.
///
/// The revision is read from [`PROTOCOL_VERSION`], not written out. It was a
/// hardcoded `"2025-11-25"` — so a conformance client probing discovery over
/// HTTP was told this server speaks a revision it refuses on every other
/// surface, by the one endpoint whose entire job is to say which revision it
/// speaks. The release notes claimed this endpoint already read the constant
/// and that `tests/discovery_metadata.rs` guarded it; neither was true, and
/// the guard is now `test_well_known_mcp_json_reports_the_real_revision`
/// below.
///
/// `roots` USED TO BE ADVERTISED HERE and has been removed. It is a CLIENT
/// capability, declared per request in `_meta`, so a server claiming it is
/// stating something that cannot be true — and this endpoint's whole job is to
/// tell a client what this server is. It was left in place once as "a separate
/// decision" because correcting it changes a payload third parties may parse;
/// 3.0.0 is where that decision is taken, alongside every other breaking wire
/// change, rather than deferred into a release that promises stability.
///
/// The three that remain are all real server capabilities and all genuinely
/// unconditional: this server registers tools, resources and prompts in every
/// build. They are still HARDCODED, which is a smaller version of the same
/// problem — nothing recomputes them from the registry, so a build that
/// dropped one would keep advertising it here.
async fn handle_mcp_discovery(State(state): State<Arc<HttpTransportState>>) -> Response {
    let bind = &state.config.bind;
    let base_url = format!("http://{bind}");

    // The SERVER's own capabilities, not a hand-written summary of them.
    //
    // This block used to be three hardcoded booleans (`"tools": true`, ...).
    // A capability is an OBJECT in this revision — `{"listChanged": true}`,
    // `{"subscribe": true, "listChanged": true}` — so the shape here did not
    // match `server/discover`, and a client that read this endpoint learned
    // something the server never said. It is the same drift the hardcoded
    // protocol version on this endpoint already caused once; the fix was not
    // extended to the field next to it.
    // No per-request `_meta` exists on this plain GET, so there is no client
    // identity to resolve — `None` is the honest argument, not a placeholder.
    // This endpoint only reads `.capabilities` below, which does not vary by
    // caller (see `handle_discover`'s doc comment), so the omission has no
    // behavioral effect today regardless.
    let capabilities = state
        .server
        .build_discovery_payload(None)
        .await
        .capabilities;

    Json(serde_json::json!({
        "mcp": {
            "version": PROTOCOL_VERSION,
            "transport": {
                "type": "streamable-http",
                "url": format!("{base_url}/mcp"),
            },
            "capabilities": capabilities,
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

/// GET /.well-known/oauth-protected-resource — Protected Resource Metadata
/// (RFC 9728).
///
/// "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata
/// (RFC9728)." Served unconditionally rather than 404-ing when OAuth is off:
/// the document describes what this resource IS and which authorization
/// servers (possibly none) can issue tokens for it, and a client probing an
/// unprotected server learns more from an empty `authorization_servers` list
/// than from a 404 it cannot distinguish from a wrong URL.
async fn handle_protected_resource_metadata(
    State(state): State<Arc<HttpTransportState>>,
) -> Response {
    let base_url = format!("http://{}", state.config.bind);
    Json(ProtectedResourceMetadata::from_config(
        &state.oauth,
        &base_url,
    ))
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
///
/// It used to report a live session count and the configured maximum. A
/// stateless transport has neither, and reporting a hardcoded zero would be
/// worse than reporting nothing: an operator watching that gauge would read
/// "no clients" rather than "this number no longer means anything".
async fn handle_health(State(state): State<Arc<HttpTransportState>>) -> Response {
    let _ = &state;
    Json(serde_json::json!({ "status": "ok" })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HttpTransportConfig::default();
        assert_eq!(config.bind, "127.0.0.1:3000");
        assert_eq!(config.max_body_size, 1_048_576);
        assert!(!config.allow_unsafe_bind);
    }

    #[test]
    fn test_default_config_oauth_disabled() {
        let config = HttpTransportConfig::default();
        assert!(!config.oauth.enabled);
    }

    #[test]
    fn test_custom_config() {
        let config = HttpTransportConfig {
            bind: "127.0.0.1:8080".to_string(),
            max_body_size: 2_097_152,
            oauth: OAuthConfig::default(),
            allowed_origins: Vec::new(),
            allow_unsafe_bind: false,
        };
        assert_eq!(config.bind, "127.0.0.1:8080");
        assert_eq!(config.max_body_size, 2_097_152);
    }

    // ========================================================================
    // Origin validation (2026-07-28 §Security & Endpoint: anti-DNS-rebinding)
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
        assert_eq!(config.allowed_origins, cloned.allowed_origins);
    }

    #[test]
    fn test_config_debug() {
        let config = HttpTransportConfig::default();
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("HttpTransportConfig"));
        assert!(debug_str.contains("3000"));
    }

    // ========================================================================
    // End-to-end Origin guard (full router) — 2026-07-28 §Security & Endpoint
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

    /// The same fixture, but handing back the `McpServer` too.
    ///
    /// `build_test_router` swallows it inside an `Arc`, which is fine until a
    /// test needs to observe server state — the subscription count, for
    /// instance — from outside the router.
    fn test_server_and_router() -> (Arc<McpServer>, Router) {
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
        let server = Arc::new(server);
        let router = build_router(Arc::clone(&server), HttpTransportConfig::default());
        (server, router)
    }

    /// Both doors must read the same bytes the same way.
    ///
    /// `serde_json::Value` keeps the LAST of two members with the same name,
    /// so routing the body through `Json<Value>` made this POST a plain
    /// `tools/call` while `parse_incoming` — used by stdio and the daemon
    /// socket — refused it as a duplicate field. Anything that read the first
    /// member disagreed with what the server ran.
    #[tokio::test]
    async fn a_duplicate_member_is_refused_on_http_as_it_is_on_stdio() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        const SMUGGLED: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"ssh_exec","arguments":{"command":"id"}},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}"#;

        // The reference door.
        let on_stdio = McpServer::parse_incoming(SMUGGLED);
        assert!(
            on_stdio.is_err(),
            "stdio must refuse a duplicate member, got {on_stdio:?}"
        );

        // The HTTP door, on the same bytes.
        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("origin", "http://localhost")
                    .header("content-type", "application/json")
                    .header("MCP-Protocol-Version", "2026-07-28")
                    .header("Mcp-Method", "tools/call")
                    .header("Mcp-Name", "ssh_exec")
                    .body(Body::from(SMUGGLED))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        let message = value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        // Named, not merely "some error": with no Origin header this request
        // is refused by the anti-DNS-rebinding guard long before the parser,
        // and the test would pass without ever reaching the code it covers.
        assert!(
            message.contains("duplicate field"),
            "HTTP must refuse it for the SAME reason stdio does, got {value}"
        );
    }

    /// Reading the body as text lost the extractor's content-type check, so
    /// it is asserted rather than assumed.
    #[tokio::test]
    async fn a_post_without_a_json_content_type_is_refused() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("origin", "http://localhost")
                    .header("content-type", "text/plain")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(modern_post(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
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

    // ============== MCP-Protocol-Version header (G-5) ==============

    #[tokio::test]
    async fn test_post_rejects_unsupported_protocol_version_header() {
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
                    .header("mcp-protocol-version", "1999-01-01")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    /// THE POSITIVE TWIN for both refusals above: a POST carrying all three
    /// required headers, correctly mirroring its body, is served.
    ///
    /// Without it, "header validation refuses X" is equally satisfied by a
    /// transport that refuses everything — and with three independent
    /// required headers there are three ways to build exactly that.
    async fn test_post_with_complete_modern_headers_is_served() {
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(modern_post(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    /// INVERTED. This asserted HTTP 200 for a POST with no
    /// `MCP-Protocol-Version`, on the 2025-11-25 rule that an absent header
    /// means "assume 2025-03-26 for backwards compatibility".
    ///
    /// 2026-07-28 replaces that rule: *"Every POST request to the MCP endpoint
    /// **MUST** include an `MCP-Protocol-Version` header"*, and a missing
    /// required standard header is a Server Validation failure — *"A required
    /// standard header (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`) is
    /// missing"* — which **MUST** be answered `400` plus `-32020`.
    ///
    /// The old behaviour was not merely obsolete, it was the door a Legacy
    /// client walked through: assuming a Legacy revision for a header-less
    /// POST is precisely how a pre-Modern client got served by a Modern-only
    /// server.
    async fn test_post_without_a_protocol_version_header_is_400_and_32020() {
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
                    .header("mcp-method", "tools/list")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).expect(
            "the 400 must carry a JSON-RPC body, not the bare string the \
                     2025-11-25 check returned",
        );
        assert_eq!(json["error"]["code"], serde_json::json!(-32020));
    }

    #[tokio::test]
    /// INVERTED, and it is the other half of the same rule change. This
    /// asserted that an explicit `2025-03-26` — the version 2025-11-25 told
    /// servers to assume — was treated exactly like an absent header, i.e.
    /// accepted.
    ///
    /// A Modern-only server speaks one revision. A client naming any other
    /// gets `-32022`, and over HTTP the spec pins the status too: *"If the
    /// server does not implement the requested protocol version ... it
    /// **MUST** respond with `400 Bad Request` and an
    /// `UnsupportedProtocolVersionError` listing its supported versions."*
    ///
    /// Note which code fires. The headers here are complete, so Server
    /// Validation passes and the request reaches the version check — this is
    /// the ordering (`-32020` before `-32022`) observed from the outside.
    async fn test_post_naming_a_legacy_protocol_version_is_400_and_32022() {
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
                    .header("mcp-protocol-version", "2025-03-26")
                    .header("mcp-method", "tools/list")
                    // Header and body name the SAME Legacy revision on purpose.
                    // They are a validated pair: disagreeing would be a header
                    // mismatch (`-32020`) and would never reach the
                    // version-support check this test is about.
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26","io.modelcontextprotocol/clientCapabilities":{}}}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], serde_json::json!(-32022));
        assert_eq!(
            json["error"]["data"]["supported"],
            serde_json::json!(["2026-07-28"]),
            "the refusal must list what the server does speak, or the client \
             cannot recover"
        );
    }

    /// The guard the release notes said already existed.
    ///
    /// `/.well-known/mcp.json` is the endpoint a conformance client reads to
    /// learn which revision this server speaks. It answered a hardcoded
    /// `"2025-11-25"` — a revision this server refuses on every other surface
    /// — while the notes claimed it read `PROTOCOL_VERSION` and that
    /// `tests/discovery_metadata.rs` guarded it. That file only checks the
    /// JSON manifests on disk and never touches this endpoint.
    ///
    /// Asserted against the CONSTANT rather than the literal `"2026-07-28"`,
    /// so the next revision bump cannot leave this endpoint behind again —
    /// a literal here would have to be found and changed by hand, which is
    /// exactly how the previous value survived a whole migration.
    #[tokio::test]
    async fn test_well_known_mcp_json_reports_the_real_revision() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/.well-known/mcp.json")
                    .header("origin", "http://localhost:5173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["mcp"]["version"], PROTOCOL_VERSION,
            "the discovery endpoint must name the revision this server actually \
             speaks: {json}"
        );
    }

    /// A POST carrying the three headers 2026-07-28 requires, DERIVED from the
    /// body rather than hardcoded.
    ///
    /// Deriving them is the point. A helper that stamped fixed header values
    /// would make every test that uses it silently exercise a MISMATCH the
    /// moment its body changed method — and a mismatch is a refusal, so the
    /// test would fail for a reason unrelated to what it asserts. Deriving
    /// keeps the request conformant by construction; a test that wants a
    /// mismatch builds it by hand, which is what makes that intent visible.
    fn modern_post(body: &str) -> axum::http::Request<axum::body::Body> {
        let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("origin", "http://localhost:5173")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", PROTOCOL_VERSION);

        if let Some(method) = parsed.get("method").and_then(Value::as_str) {
            builder = builder.header("mcp-method", method);
            if let Some((_, field)) = MCP_NAME_METHODS.iter().find(|(m, _)| *m == method)
                && let Some(name) = parsed
                    .get("params")
                    .and_then(|params| params.get(field))
                    .and_then(Value::as_str)
            {
                builder = builder.header("mcp-name", name);
            }
        }

        builder
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    /// The header and the envelope must AGREE about the revision.
    ///
    /// They are a header/body pair, so a disagreement is a mismatch under the
    /// same rule as `Mcp-Method` — and the answer is `-32020`, not `-32022`.
    /// The distinction matters to a client: "your two copies disagree" is
    /// actionable, while "I do not speak 2026-07-28" would be nonsense when
    /// the header said exactly that.
    ///
    /// Both values here are ones the server DOES support, which is what makes
    /// the test about disagreement rather than about support.
    #[tokio::test]
    async fn test_header_and_envelope_revisions_must_agree() {
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
                    .header("mcp-protocol-version", "2026-07-28")
                    .header("mcp-method", "tools/list")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["error"]["code"],
            serde_json::json!(-32020),
            "a header/body disagreement is a MISMATCH, not an unsupported \
             version: {json}"
        );
    }

    /// THE POSITIVE TWIN: agreeing copies are served.
    ///
    /// Without it, "the two must agree" is satisfied by a gate that refuses
    /// every request carrying a revision in its envelope at all — which is
    /// every conformant Modern client.
    #[tokio::test]
    async fn test_agreeing_header_and_envelope_revisions_are_served() {
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(modern_post(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ============== Stateless transport: no session, no GET, no DELETE ==============

    /// `GET /mcp` is gone, and answers `405` rather than `404`.
    ///
    /// The path exists and the METHOD does not. A `404` would tell a client
    /// the endpoint is absent and send it looking for another one; a `405`
    /// with `Allow` tells it exactly what to do instead.
    #[tokio::test]
    async fn test_get_on_mcp_is_405_with_allow_post() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mcp")
                    .header("origin", "http://localhost:5173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response
                .headers()
                .get("allow")
                .and_then(|v| v.to_str().ok()),
            Some("POST"),
            "a 405 without `Allow` leaves the client guessing"
        );
    }

    /// `DELETE /mcp` closed a session. There is no session.
    #[tokio::test]
    async fn test_delete_on_mcp_is_405() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/mcp")
                    .header("origin", "http://localhost:5173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// No response carries `Mcp-Session-Id` any more.
    ///
    /// Asserted on a SERVED request rather than a refused one: a refusal
    /// might plausibly skip the header for unrelated reasons, so proving its
    /// absence on the happy path is what shows the lifecycle is gone rather
    /// than merely bypassed.
    #[tokio::test]
    async fn test_no_response_carries_a_session_id_header() {
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(modern_post(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get("mcp-session-id").is_none(),
            "the session lifecycle is gone; handing out an id for a session \
             that does not exist is what the old code did"
        );
    }

    // ============== subscriptions/listen as the POST response body ==============

    /// The replacement for the GET endpoint: an accepted `subscriptions/listen`
    /// answers on ITS OWN POST body, as a stream that stays open.
    ///
    /// Two things are asserted and both are needed. The content type shows the
    /// server chose the streaming half of the spec's disjunction; the first
    /// frame shows the stream is LIVE and carries the acknowledgement, which a
    /// content-type check alone would not — a handler returning an
    /// `text/event-stream` header over an empty, immediately-closed body would
    /// pass the first assertion and fail every client.
    #[tokio::test]
    async fn test_subscriptions_listen_answers_with_a_live_sse_stream() {
        use tokio_stream::StreamExt as _;
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(modern_post(
                r#"{"jsonrpc":"2.0","id":7,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            content_type.starts_with("text/event-stream"),
            "listen must answer with the streaming half of the disjunction, \
             got {content_type}"
        );

        let mut body = response.into_body().into_data_stream();
        let frame = tokio::time::timeout(std::time::Duration::from_secs(3), body.next())
            .await
            .expect("no SSE frame within 3s — the stream is open but silent")
            .expect("the stream ended without a frame")
            .expect("body error");
        let text = String::from_utf8_lossy(&frame);
        assert!(
            text.contains("notifications/subscriptions/acknowledged"),
            "the first message on the stream must be the acknowledgement: {text}"
        );
    }

    /// A REFUSED listen answers as JSON, not as a stream.
    ///
    /// It has no stream to hold open, and answering `text/event-stream`
    /// anyway would leave the client waiting on a body that will never carry
    /// anything — a hang instead of an error.
    ///
    /// The refusal here is C3's: the request declares no capabilities.
    #[tokio::test]
    async fn test_a_refused_listen_answers_json_not_a_stream() {
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
                    .header("mcp-protocol-version", "2026-07-28")
                    .header("mcp-method", "subscriptions/listen")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":7,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            !content_type.starts_with("text/event-stream"),
            "a refusal must not be dressed as a stream: {content_type}"
        );
    }

    /// THE STREAM GUARD FIRES. Dropping the response body drops the
    /// subscription.
    ///
    /// This is the guarantee the migration notes said had to be owned by the
    /// stream rather than by the handler, and it has no observable other than
    /// the registry count — the guard runs on `Drop`, so asserting that the
    /// guard EXISTS asserts nothing about whether it RUNS.
    ///
    /// Three measurement points, because fewer would not separate the
    /// failure modes: zero before (the fixture is clean), one while the
    /// stream is live (registration happened at all), zero after the drop
    /// (the guard fired). Asserting only the last is satisfied by a server
    /// that never registered anything.
    #[tokio::test]
    async fn test_dropping_the_listen_stream_drops_the_subscription() {
        use tokio_stream::StreamExt as _;
        use tower::ServiceExt;

        let (server, router) = test_server_and_router();
        assert_eq!(server.live_subscription_count(), 0);

        let response = router
            .oneshot(modern_post(
                r#"{"jsonrpc":"2.0","id":7,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
            ))
            .await
            .unwrap();

        let mut body = response.into_body().into_data_stream();
        let _ack = tokio::time::timeout(std::time::Duration::from_secs(3), body.next())
            .await
            .expect("no acknowledgement within 3s")
            .expect("stream ended")
            .expect("body error");
        assert_eq!(
            server.live_subscription_count(),
            1,
            "the subscription must be live while the stream is"
        );

        drop(body);
        // The guard runs on drop of the stream the closure captured it into;
        // yield so the drop is observed before the assertion.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(
            server.live_subscription_count(),
            0,
            "dropping the stream must drop the subscription, or a disconnected \
             client's filter keeps matching forever"
        );
    }

    // ============== Server Validation: the three required headers ==============

    /// THE test obligation 2 exists for.
    ///
    /// A Legacy client opens with `initialize` and, from 2025-06-18 onward,
    /// DOES send `MCP-Protocol-Version` — so its POST trips two MUSTs at once:
    /// `Mcp-Method` is missing (header validation) and the version is
    /// unsupported. The spec states no precedence between them, but the
    /// Compatibility Matrix resolves this exact row: *"HTTP: the request is
    /// missing the required headers and is rejected per server validation with
    /// `400 Bad Request`"*.
    ///
    /// So the assertion is `-32020`, and asserting it is what makes the
    /// ORDERING observable from outside: with the checks the other way round
    /// this same request answers `-32022` and the test reds. Until this
    /// landed, the HTTP path answered `-32022` and was non-conformant, which
    /// `handle_initialize`'s doc comment said in as many words.
    #[tokio::test]
    async fn test_legacy_initialize_over_http_is_400_and_32020_not_32022() {
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
                    // A Legacy client sends this, and nothing else.
                    .header("mcp-protocol-version", "2025-11-25")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"legacy","version":"1.0.0"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["error"]["code"],
            serde_json::json!(-32020),
            "header validation must run BEFORE version support: a -32022 here \\
             means the two checks are the wrong way round, which the \\
             compatibility matrix resolves against: {json}"
        );
    }

    /// A missing `Mcp-Method` on an otherwise well-formed Modern request.
    ///
    /// Separate from the `initialize` test above even though both refuse for
    /// the same reason: that one is a Legacy client and could pass for the
    /// wrong reason if the server refused `initialize` by name rather than by
    /// header. This one uses a method the server serves happily.
    #[tokio::test]
    async fn test_post_without_mcp_method_header_is_400_and_32020() {
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
                    .header("mcp-protocol-version", "2026-07-28")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], serde_json::json!(-32020));
    }

    /// A PRESENT but CONTRADICTING `Mcp-Method`.
    ///
    /// The other half of the code's definition, and the half the spec's
    /// opening sentence is actually about: *"reject requests where the values
    /// specified in the headers do not match the corresponding values in the
    /// request body"*. Absence and mismatch are different failures behind one
    /// code, so each needs its own test — a gate that only checked presence
    /// would pass the test above and let a gateway route on a header that
    /// lies about the body, which is the attack the header exists to prevent.
    #[tokio::test]
    async fn test_post_with_a_lying_mcp_method_header_is_400_and_32020() {
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
                    .header("mcp-protocol-version", "2026-07-28")
                    // Says `tools/list`; the body says `tools/call`.
                    .header("mcp-method", "tools/list")
                    .header("mcp-name", "ssh_exec")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ssh_exec","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], serde_json::json!(-32020));
    }

    /// `Mcp-Name` is required for exactly three methods, and `tools/call` is
    /// one of them. Its absence is a validation failure even when
    /// `Mcp-Method` is present and correct.
    #[tokio::test]
    async fn test_tools_call_without_mcp_name_header_is_400_and_32020() {
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
                    .header("mcp-protocol-version", "2026-07-28")
                    .header("mcp-method", "tools/call")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ssh_status","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], serde_json::json!(-32020));
    }

    /// `Mcp-Name` is NOT required for a method outside the table of three, and
    /// this is the boundary rather than a formality.
    ///
    /// The table says which methods REQUIRE the header, not which may carry
    /// it. A gate that demanded `Mcp-Name` everywhere would refuse every
    /// `tools/list` in existence while passing all four tests above.
    #[tokio::test]
    async fn test_a_method_outside_the_table_needs_no_mcp_name() {
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(modern_post(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    /// RFC 9728 is a MUST for an MCP server: "MCP servers MUST implement OAuth
    /// 2.0 Protected Resource Metadata (RFC9728). MCP clients MUST use OAuth
    /// 2.0 Protected Resource Metadata for authorization server discovery."
    /// The route did not exist at all.
    ///
    /// Served even with OAuth disabled: a client probing an unprotected server
    /// learns more from an empty `authorization_servers` list than from a 404
    /// it cannot distinguish from a wrong URL.
    #[tokio::test]
    async fn the_protected_resource_metadata_endpoint_exists() {
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/.well-known/oauth-protected-resource")
                    .header("origin", "http://localhost:5173")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["resource"].is_string(),
            "`resource` is the one REQUIRED field: {json}"
        );
        // snake_case, not camelCase: RFC 9728 field names are snake_case like
        // every other OAuth metadata document, and unlike the MCP wire types in
        // this crate. Getting it wrong makes the document unreadable to an
        // RFC-9728 client while still looking plausible in a test.
        assert_eq!(
            json["bearer_methods_supported"],
            serde_json::json!(["header"])
        );
    }

    // ============== Mcp-Name Base64 sentinel ==============

    /// The spec's own encoding table, used as test vectors.
    ///
    /// Four rows, each covering a distinct reason a value cannot travel as a
    /// plain header: non-ASCII, edge whitespace, a control character, and a
    /// literal value that happens to look like the wrapper.
    #[test]
    fn the_sentinel_decodes_the_specs_own_examples() {
        for (encoded, expected) in [
            ("=?base64?SGVsbG8sIOS4lueVjA==?=", "Hello, 世界"),
            ("=?base64?IHBhZGRlZCA=?=", " padded "),
            ("=?base64?bGluZTEKbGluZTI=?=", "line1\nline2"),
            ("=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=", "=?base64?literal?="),
        ] {
            assert_eq!(
                decode_header_sentinel(encoded).expect("a spec example decodes"),
                expected,
                "decoding {encoded}"
            );
        }
    }

    /// A value without the wrapper is literal and is NOT decoded.
    ///
    /// Clients resolve the ambiguity from their side by encoding any
    /// plain-ASCII value that matches the sentinel pattern, so an unwrapped
    /// value can always be taken at face value. A decoder that tried Base64
    /// opportunistically would corrupt ordinary tool names, most of which are
    /// valid Base64 by accident.
    #[test]
    fn an_unwrapped_value_is_returned_untouched() {
        for literal in ["ssh_exec", "file:///etc/hosts", "", "=?base64?", "?="] {
            assert_eq!(
                decode_header_sentinel(literal).expect("a literal is not decoded"),
                literal
            );
        }
    }

    /// A wrapper whose payload is not Base64, or not UTF-8, is a validation
    /// failure rather than a silent pass-through.
    #[test]
    fn a_malformed_sentinel_payload_is_an_error() {
        assert!(decode_header_sentinel("=?base64?not base64!?=").is_err());
        // `/w==` is a valid Base64 encoding of the single byte 0xFF, which is
        // not valid UTF-8 on its own.
        assert!(decode_header_sentinel("=?base64?/w==?=").is_err());
    }

    /// END TO END, and the reason this whole block exists: a conforming client
    /// reading a resource whose URI is not plain-ASCII-safe MUST send the
    /// encoded form, and used to be refused `-32020` for a mismatch that did
    /// not exist. The better the client conformed, the more reliably it was
    /// rejected.
    #[test]
    fn an_encoded_mcp_name_matches_a_non_ascii_body_uri() {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-protocol-version", "2026-07-28".parse().unwrap());
        headers.insert("mcp-method", "resources/read".parse().unwrap());
        // "file:///srv/données.txt"
        headers.insert(
            "mcp-name",
            "=?base64?ZmlsZTovLy9zcnYvZG9ubsOpZXMudHh0?="
                .parse()
                .unwrap(),
        );

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": { "uri": "file:///srv/données.txt" }
        });

        assert!(
            check_modern_headers(&headers, &body).is_ok(),
            "a correctly encoded Mcp-Name must be accepted"
        );
    }

    /// THE NEGATIVE TWIN. Decoding must not become "accept anything wrapped":
    /// an encoded value that decodes to something else is still a mismatch.
    /// Without this, deleting the comparison entirely would leave the test
    /// above green.
    #[test]
    fn an_encoded_mcp_name_that_decodes_to_a_different_value_is_a_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-protocol-version", "2026-07-28".parse().unwrap());
        headers.insert("mcp-method", "tools/call".parse().unwrap());
        // "ssh_exec"
        headers.insert("mcp-name", "=?base64?c3NoX2V4ZWM=?=".parse().unwrap());

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "ssh_reboot" }
        });

        let err = check_modern_headers(&headers, &body)
            .expect_err("a decoded value that differs is still a mismatch");
        assert_eq!(err.code, -32020, "{err:?}");
    }

    // ============== C3: mandatory clientCapabilities over HTTP ==============

    /// The stdio dispatcher answers this `-32602` on its own; what it cannot
    /// do is set an HTTP status, because it has no idea which transport is
    /// calling it. So the status is asserted here, and the BODY is asserted
    /// too — a bare 400 with an unparsable string body (which is what
    /// `validate_protocol_version` still returns) leaves a JSON-RPC client
    /// with nothing to act on.
    #[tokio::test]
    async fn test_post_without_client_capabilities_is_400_with_a_jsonrpc_body() {
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(modern_post(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body)
            .expect("the 400 must carry a parseable JSON-RPC body, not a bare string");
        assert_eq!(json["error"]["code"], serde_json::json!(-32602));
        assert_eq!(
            json["id"],
            serde_json::json!(1),
            "the refusal must be addressed to the request it refuses"
        );
    }

    /// THE POSITIVE TWIN. The same request with an empty `{}` envelope is
    /// served at 200. Without it, "capability-less POSTs get 400" is equally
    /// satisfied by a transport that 400s everything.
    #[tokio::test]
    async fn test_post_with_empty_client_capabilities_is_200() {
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(
                modern_post(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ============== Notification suppression (G-18) ==============
    //
    // JSON-RPC 2.0 §4.1/§5: a Notification is a Request with no `id`, and
    // "the receiver must not send a response to a notification". This path
    // built and returned a full JsonRpcResponse regardless. Mirrors the stdio
    // fix (`McpServer::route_incoming_message`, gated on `message.id.is_none()`,
    // not on the method name).
    //
    // Status code: the Streamable HTTP transport spec MUST-requires 202
    // Accepted with no body when the POST body is solely a notification (or a
    // response).
    //
    // A `///` block stood above this one until 3.0.0, describing a batch test
    // that had already been deleted. Having nothing left to document, it
    // re-attached itself to the FIRST TEST BELOW, which is about something
    // else entirely — the same failure as the orphaned `#[cfg]` and the
    // orphaned `SessionCapabilities` doc comment. Removing an item is never
    // one edit.

    #[tokio::test]
    async fn test_post_single_notification_gets_no_response_body() {
        use tower::ServiceExt;

        // "ping" is an ordinary request method with no "notifications/"
        // prefix — omitting `id` is what makes this a notification, not the
        // method name. Proves the gate is id-based, not prefix-based.
        let response = build_test_router()
            .oneshot(modern_post(r#"{"jsonrpc":"2.0","method":"ping"}"#))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            body.is_empty(),
            "a notification must get no JSON-RPC response body, got: {body:?}"
        );
    }

    #[tokio::test]
    async fn test_post_request_named_like_notification_still_answered() {
        use tower::ServiceExt;

        // Method name suggests a notification, but `id` is present — this
        // IS a request per JSON-RPC 2.0 and MUST still be answered. Proves
        // the gate does not special-case by method name in either direction.
        let response = build_test_router()
            .oneshot(
                modern_post(r#"{"jsonrpc":"2.0","id":7,"method":"notifications/initialized","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#),
            )
            .await
            .unwrap();

        // The SUBJECT is that it was answered at all rather than swallowed as
        // a notification, so that is what is asserted: not `202`, and a body
        // carrying the id.
        //
        // The status is `404` rather than `200` because `notifications/
        // initialized` is one of the methods 3.0.0 removed, so this reaches
        // the `-32601` path — a separate MUST, pinned separately by
        // `an_unimplemented_method_is_404_with_method_not_found`. Asserting
        // `OK` here made this test fail for a reason having nothing to do with
        // the id gate it exists to guard.
        assert_ne!(
            response.status(),
            StatusCode::ACCEPTED,
            "a message with an `id` is a request and must be answered"
        );
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], serde_json::json!(7), "status was {status}");
    }

    /// "If the server does not implement the requested RPC method, it MUST
    /// respond with `404 Not Found` and a JSON-RPC error with code `-32601`
    /// (`Method not found`)."
    ///
    /// The body was already correct and the status was `200`. The two are a
    /// pair, and the spec says so in the same paragraph: "The JSON-RPC error
    /// body distinguishes this case from a `404` returned by a legacy HTTP+SSE
    /// server that does not host the modern MCP endpoint." `404` says "not
    /// here"; the body says "this IS the endpoint, that method is not".
    ///
    /// `200` broke the client half of that: a dual-era client falls back to
    /// `initialize` on `400`/`404`/`405` unless the body is a recognised
    /// modern error, and `200` is not a status it inspects at all.
    #[tokio::test]
    async fn an_unimplemented_method_is_404_with_method_not_found() {
        use tower::ServiceExt;

        let response = build_test_router()
            .oneshot(modern_post(
                r#"{"jsonrpc":"2.0","id":3,"method":"nope/definitely_not_a_method","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["error"]["code"],
            serde_json::json!(-32601),
            "the 404 must carry the JSON-RPC body that distinguishes it from a \
             legacy server's 404: {json}"
        );
        assert_eq!(json["id"], serde_json::json!(3), "{json}");
    }

    /// The counterweight, and without it the test above is a licence to answer
    /// `404` for everything.
    ///
    /// Only `-32601` is remapped. Every other JSON-RPC error comes from a
    /// method this server DOES implement, and remapping those would tell a
    /// client the endpoint is missing whenever a tool rejected its arguments —
    /// which is exactly the fallback-to-`initialize` trigger this change
    /// exists to get right.
    #[tokio::test]
    async fn an_implemented_method_that_errors_is_still_200() {
        use tower::ServiceExt;

        // A real method, given arguments it must refuse: `-32602`, not
        // `-32601`.
        let response = build_test_router()
            .oneshot(modern_post(
                r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"definitely_not_a_tool","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
            ))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a fault inside an implemented method is not a missing endpoint"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_ne!(
            json["error"]["code"],
            serde_json::json!(-32601),
            "this test only means something while the error is NOT method-not-found: {json}"
        );
    }

    #[tokio::test]
    /// REPLACES the three batch tests, which asserted per-member answers, a
    /// 202 for an all-notification batch, and a 200 for a mixed one.
    ///
    /// JSON-RPC batching was removed in revision 2025-06-18 ("Remove support
    /// for JSON-RPC batching", Major changes #1) and 2026-07-28 does not
    /// bring it back: `JSONRPCMessage` is `JSONRPCRequest | JSONRPCNotification
    /// | JSONRPCResponse`, and the string "batch" does not occur anywhere in
    /// the published schema. Streamable HTTP states it directly: *"The body of
    /// the HTTP POST **MUST** be a single JSON-RPC _request_ or
    /// _notification_."*
    ///
    /// The CODE is this server's choice and the test says so: the spec states
    /// the client-side MUST but enumerates no server-side procedure for an
    /// array body, so `-32600 Invalid Request` is reasoned from JSON-RPC
    /// rather than quoted from MCP.
    async fn test_post_refuses_a_json_array_body() {
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
                    .header("mcp-protocol-version", "2026-07-28")
                    .body(Body::from(r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], serde_json::json!(-32600));
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("batching"),
            "the refusal must name the reason, or a client sees only \
             `Invalid Request`: {json}"
        );
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
        let r = serve(server, cfg, None).await;
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
        let handle = tokio::spawn(async move { serve(server, cfg, None).await });
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
