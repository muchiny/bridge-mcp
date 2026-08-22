//! OAuth 2.0 Authentication Middleware for MCP HTTP Transport
//!
//! Validates Bearer tokens on incoming HTTP requests when OAuth is enabled.
//! Tokens are verified as JWTs against a configured set of public keys
//! (RSA or ECDSA family — HMAC algorithms are rejected to prevent
//! `alg`-confusion attacks).
//!
//! # Production wiring
//!
//! Use [`build_validator`] at server startup to construct a single
//! [`OAuthValidator`] from a [`HttpOAuthConfig`](crate::config::types::HttpOAuthConfig).
//! The validator pre-loads
//! every signing key declared in `static_keys` and is shared across
//! requests as `Arc<OAuthValidator>` via Axum extensions; the middleware
//! reads the shared instance instead of building a fresh empty validator
//! per request. `build_validator` returns `Err` when OAuth is enabled but
//! no key source is configured, so the server fails closed at boot
//! rather than rejecting every token.
//!
//! # Limitations
//!
//! JWKS HTTP fetching (`jwks_uri`) is not yet wired here: the `http`
//! feature does not pull in an HTTP client, so the configuration field is
//! reserved but currently rejected by `build_validator` with a clear
//! error. Until reqwest/hyper are piped through extensions, populate the
//! validator via `static_keys`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header::WWW_AUTHENTICATE};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, warn};

/// OAuth configuration for the HTTP transport.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthConfig {
    /// Enable OAuth authentication (default: false).
    #[serde(default)]
    pub enabled: bool,
    /// Expected issuer (e.g., `"https://auth.example.com"`).
    #[serde(default)]
    pub issuer: String,
    /// Expected audience.
    #[serde(default)]
    pub audience: String,
    /// JWKS endpoint for key validation (auto-discovered from issuer if not set).
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// OAuth client ID for this server.
    #[serde(default)]
    pub client_id: String,
    /// Required scopes for access.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// Static signing keys, keyed by `kid`. Populated from
    /// [`crate::config::types::HttpOAuthConfig::static_keys`] at boot;
    /// kept on the runtime config so [`build_validator`] can pre-load
    /// the validator's key map.
    #[serde(default)]
    pub static_keys: Vec<(String, String)>,
    /// Absolute URL of this server's Protected Resource Metadata document.
    ///
    /// Runtime-populated at boot from the HTTP bind address, like
    /// [`Self::static_keys`] — it is not a YAML key, because it describes where
    /// this process is listening rather than what the operator configured.
    ///
    /// Needed because it is the ONLY thing that makes the 401 actionable: the
    /// authorization flow has the client "Extract `resource_metadata` URL from
    /// WWW-Authenticate", then fetch that document to learn which
    /// authorization server to talk to. Without it a client gets a bare 401 and
    /// no way to discover where to authenticate.
    #[serde(default)]
    pub resource_metadata_url: String,
}

/// The `WWW-Authenticate` challenge sent with a 401 or a 403.
///
/// RFC 6750 §3 `Bearer` scheme with the parameters MCP names:
/// `resource_metadata` (the discovery pointer), `scope` (what this operation
/// needs), and on a 403 `error="insufficient_scope"`.
///
/// Built as a `String` and parsed into a `HeaderValue`, dropping the header
/// entirely if the parse fails. A config value with a control character in it
/// would otherwise panic or corrupt the response; losing the challenge
/// degrades discovery, which is strictly better.
fn bearer_challenge(config: &OAuthConfig, error: Option<&str>) -> Option<HeaderValue> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(error) = error {
        parts.push(format!("error=\"{error}\""));
    }
    if !config.required_scopes.is_empty() {
        parts.push(format!("scope=\"{}\"", config.required_scopes.join(" ")));
    }
    if !config.resource_metadata_url.is_empty() {
        parts.push(format!(
            "resource_metadata=\"{}\"",
            config.resource_metadata_url
        ));
    }
    let value = if parts.is_empty() {
        "Bearer".to_string()
    } else {
        format!("Bearer {}", parts.join(", "))
    };
    HeaderValue::from_str(&value).ok()
}

/// Why a Bearer token was refused.
///
/// The two arms carry different HTTP statuses, so folding them into one
/// `String` (as this did) forced every scope failure to answer `401`. The
/// error-handling table is explicit that they are different answers: `401`
/// means "Authorization required or token invalid", `403` means "Invalid
/// scopes or insufficient permissions". A client that gets `401` for a scope
/// problem re-authenticates identically and loops.
#[derive(Debug, Clone)]
pub enum TokenError {
    /// The token is missing, malformed, expired, or not for this audience.
    Invalid(String),
    /// The token is valid but does not carry the scopes this server requires.
    InsufficientScope {
        /// Every scope still missing — not just the first.
        missing: Vec<String>,
    },
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "{message}"),
            Self::InsufficientScope { missing } => {
                write!(f, "Missing required scope(s): {}", missing.join(" "))
            }
        }
    }
}

/// Validated token claims extracted from a Bearer token.
#[derive(Debug, Clone)]
pub struct TokenClaims {
    /// Subject (user/client identifier).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Scopes granted.
    pub scopes: Vec<String>,
}

impl TokenClaims {
    /// Check if the token has a specific scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// MCP-specific OAuth scopes.
pub mod scopes {
    /// Read tool definitions.
    pub const TOOLS_READ: &str = "mcp:tools:read";
    /// Execute tools.
    pub const TOOLS_EXECUTE: &str = "mcp:tools:execute";
    /// Read resources.
    pub const RESOURCES_READ: &str = "mcp:resources:read";
    /// Admin operations (logging, tasks).
    pub const ADMIN: &str = "mcp:admin";
}

/// Internal JWT claims layout deserialised from the verified token payload.
#[derive(Debug, Deserialize)]
struct JwtClaims {
    #[serde(default)]
    sub: Option<String>,
    iss: String,
    /// `aud` may be a single string or an array per RFC 7519 §4.1.3.
    /// `jsonwebtoken` validates it through [`Validation::set_audience`]; we
    /// only need to deserialise it without rejecting either shape.
    #[allow(dead_code)]
    aud: serde_json::Value,
    #[serde(default)]
    scope: String,
    #[allow(dead_code)]
    exp: i64,
    #[serde(default)]
    #[allow(dead_code)]
    nbf: Option<i64>,
}

/// OAuth validator that checks Bearer tokens.
///
/// Tokens must be JWTs signed with one of the accepted asymmetric algorithms
/// (`RS256`/`RS384`/`RS512`, `ES256`/`ES384`, `PS256`/`PS384`/`PS512`).
/// HMAC algorithms (`HS*`) and `none` are rejected to prevent
/// `alg`-confusion attacks.
///
/// Public keys are addressed by their JWK `kid`. Two key shapes are accepted:
/// - PEM-encoded RSA public key (PKCS#1 or `SubjectPublicKeyInfo`)
/// - `n.e` JWK components stored as `"<n>.<e>"` (populated by
///   [`OAuthValidator::load_jwks`])
pub struct OAuthValidator {
    config: OAuthConfig,
    /// Public keys keyed by `kid`. Each value is either a PEM blob or the
    /// `n.e` JWK components when populated by [`Self::load_jwks`].
    keys: HashMap<String, String>,
}

impl OAuthValidator {
    /// Create a new OAuth validator with no signing keys.
    ///
    /// Callers must populate keys via [`Self::set_static_keys`] or
    /// [`Self::load_jwks`] before any token will be accepted.
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            keys: HashMap::new(),
        }
    }

    /// Replace the in-memory key map with the supplied `(kid, pem)` pairs.
    pub fn set_static_keys(&mut self, keys: Vec<(String, String)>) {
        self.keys = keys.into_iter().collect();
    }

    /// Number of signing keys currently loaded (mostly useful in tests).
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Replace the in-memory key map from a parsed JWKS document.
    ///
    /// The document must follow RFC 7517 (`{ "keys": [ { "kid": ..., "n":
    /// ..., "e": ... } ] }`). The HTTP fetch is intentionally not bundled
    /// here so the `http` feature does not pull in an HTTP client; callers
    /// (or a follow-up that pipes `reqwest`/`hyper` through extensions)
    /// fetch the document and pass the parsed JSON in.
    ///
    /// # Errors
    /// Returns a string describing the parse failure.
    pub fn load_jwks(&mut self, jwks: &serde_json::Value) -> Result<(), String> {
        let mut keys = HashMap::new();
        for k in jwks["keys"].as_array().ok_or("jwks.keys not an array")? {
            let kid = k["kid"].as_str().unwrap_or_default().to_string();
            let n = k["n"].as_str().ok_or("jwk.n missing")?;
            let e = k["e"].as_str().ok_or("jwk.e missing")?;
            keys.insert(kid, format!("{n}.{e}"));
        }
        self.keys = keys;
        Ok(())
    }

    /// Validate a Bearer token string.
    ///
    /// Verifies the JWT signature against the configured public key map,
    /// enforces `iss`/`aud`/`exp`/`nbf` (with 30s leeway) and the configured
    /// `required_scopes`. Returns the extracted claims on success.
    ///
    /// # Errors
    /// Returns a human-readable description of the first validation failure.
    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, TokenError> {
        // Decode the unverified header to learn the algorithm and key id.
        let header = decode_header(token)
            .map_err(|e| TokenError::Invalid(format!("Invalid JWT header: {e}")))?;

        // Reject HMAC and `none` algorithms to prevent alg-confusion attacks.
        match header.alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {}
            other => {
                return Err(TokenError::Invalid(format!(
                    "Algorithm '{other:?}' not accepted"
                )));
            }
        }

        let kid = header
            .kid
            .ok_or_else(|| TokenError::Invalid("JWT missing kid header".to_string()))?;
        let key_material = self
            .keys
            .get(&kid)
            .ok_or_else(|| TokenError::Invalid(format!("Unknown JWT signing key: {kid}")))?;

        let decoding_key = if let Some((n, e)) = key_material.split_once('.') {
            DecodingKey::from_rsa_components(n, e)
                .map_err(|err| TokenError::Invalid(format!("Invalid JWKS RSA components: {err}")))?
        } else {
            DecodingKey::from_rsa_pem(key_material.as_bytes())
                .map_err(|err| TokenError::Invalid(format!("Invalid PEM signing key: {err}")))?
        };

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        // Explicitly require all four spec claims. `jsonwebtoken` 9.x only
        // requires `exp` by default; without this line a token missing
        // `sub` would pass validation. `iss`/`aud` enforcement is already
        // implied by `set_issuer`/`set_audience` above, but listing them
        // here keeps the contract explicit (FIND-007).
        validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 30;

        let data = decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| TokenError::Invalid(format!("JWT validation failed: {e}")))?;

        let scopes: Vec<String> = data
            .claims
            .scope
            .split_whitespace()
            .map(String::from)
            .collect();

        // EVERY missing scope, not the first. The spec: "servers SHOULD
        // include all scopes required for the current operation in a single
        // challenge. Challenging incrementally (returning one missing scope,
        // then another on the subsequent retry) forces multiple authorization
        // round-trips for a single operation and degrades user experience."
        // The early `return` here was exactly that incremental challenge.
        let missing: Vec<String> = self
            .config
            .required_scopes
            .iter()
            .filter(|required| !scopes.iter().any(|s| s == *required))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(TokenError::InsufficientScope { missing });
        }

        Ok(TokenClaims {
            sub: data.claims.sub.unwrap_or_default(),
            iss: data.claims.iss,
            scopes,
        })
    }
}

/// Build an [`OAuthValidator`] from a YAML config: pre-populates static
/// keys so token validation succeeds at request time rather than per-
/// request constructing an empty key map.
///
/// JWKS HTTP fetching is not yet wired here — see the module-level
/// "Limitations" section. When `jwks_uri` is configured but no static
/// keys are present, this function returns an explicit error rather
/// than silently building a validator that rejects every token.
///
/// # Errors
/// Returns `Err` when OAuth is enabled but no usable key source is
/// configured, so the server fails closed at boot.
// Async because the FIND-006 follow-up will replace the
// `jwks_uri` rejection with an actual fetch (`reqwest`/`hyper`),
// and the public signature should not need to change again.
#[allow(clippy::unused_async)]
pub async fn build_validator(
    cfg: &crate::config::types::HttpOAuthConfig,
) -> Result<OAuthValidator, String> {
    let runtime_cfg = OAuthConfig {
        // Filled in by the HTTP transport at boot, which is the only place
        // that knows the bind address this process is actually listening on.
        resource_metadata_url: String::new(),
        enabled: cfg.enabled,
        issuer: cfg.issuer.clone(),
        audience: cfg.audience.clone(),
        jwks_uri: cfg.jwks_uri.clone(),
        client_id: cfg.client_id.clone(),
        required_scopes: cfg.required_scopes.clone(),
        static_keys: cfg
            .static_keys
            .iter()
            .map(|k| (k.kid.clone(), k.public_key_pem.clone()))
            .collect(),
    };

    build_validator_from_runtime(&runtime_cfg).await
}

/// Build an [`OAuthValidator`] from the runtime [`OAuthConfig`].
///
/// Used by the HTTP server start-up path, which already converts the
/// YAML config into the runtime shape before constructing
/// [`super::http::HttpTransportConfig`]. Same fail-closed semantics as
/// [`build_validator`].
///
/// # Errors
/// Returns `Err` when OAuth is enabled but no usable key source is
/// configured.
// See `build_validator` — async kept to absorb the FIND-006 follow-up
// (JWKS HTTP fetch) without breaking the public signature.
#[allow(clippy::unused_async)]
pub async fn build_validator_from_runtime(cfg: &OAuthConfig) -> Result<OAuthValidator, String> {
    let mut v = OAuthValidator::new(cfg.clone());

    if !cfg.static_keys.is_empty() {
        v.set_static_keys(cfg.static_keys.clone());
    }

    if cfg.jwks_uri.is_some() && v.key_count() == 0 {
        return Err(
            "oauth.jwks_uri configured but JWKS HTTP fetching is not yet wired; \
             configure oauth.static_keys for now (FIND-006 follow-up will pipe \
             reqwest through extensions)"
                .into(),
        );
    }

    if cfg.enabled && v.key_count() == 0 {
        return Err(
            "oauth.enabled=true but no static_keys (or supported jwks_uri) configured; \
             refusing to start with an empty key map"
                .into(),
        );
    }

    Ok(v)
}

/// Axum middleware that validates OAuth Bearer tokens.
///
/// Reads the shared `Arc<OAuthValidator>` installed by [`build_validator`]
/// from request extensions. When the validator extension is absent (server
/// misconfiguration) the request is rejected with HTTP 503 rather than
/// silently falling back to an empty key map.
pub async fn oauth_middleware(request: Request, next: Next) -> Response {
    // Extract the OAuth config from extensions
    let config = request.extensions().get::<Arc<OAuthConfig>>().cloned();

    let Some(config) = config else {
        // No OAuth config in extensions — pass through
        return next.run(request).await;
    };

    if !config.enabled {
        return next.run(request).await;
    }

    // Extract Bearer token
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let Some(auth) = auth_header else {
        return unauthorized(&config, "Missing Authorization header");
    };

    let Some(token) = auth.strip_prefix("Bearer ") else {
        return unauthorized(&config, "Invalid Authorization scheme, expected Bearer");
    };
    let token = token.trim();

    // Read the boot-time validator from extensions. If it is missing the
    // server was wired incorrectly — fail closed with 503 rather than
    // building a fresh empty validator that rejects every token.
    let Some(validator) = request.extensions().get::<Arc<OAuthValidator>>().cloned() else {
        warn!("OAuthValidator extension missing — server misconfigured");
        return service_unavailable("OAuth validator not configured on this server");
    };
    match validator.validate_token(token) {
        Ok(claims) => {
            debug!(sub = %claims.sub, scopes = ?claims.scopes, "Token validated");
            next.run(request).await
        }
        // 401 and 403 are DIFFERENT answers and the table says so: 401 is
        // "Authorization required or token invalid", 403 is "Invalid scopes or
        // insufficient permissions". Both used to be 401, so a client short a
        // scope re-authenticated with the same scope set and looped.
        Err(TokenError::InsufficientScope { missing }) => {
            warn!(missing = ?missing, "Token lacks required scopes");
            insufficient_scope(&config, &missing)
        }
        Err(e) => {
            warn!(error = %e, "Token validation failed");
            unauthorized(&config, &e.to_string())
        }
    }
}

fn service_unavailable(message: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(json!({
            "error": "service_unavailable",
            "message": message,
        })),
    )
        .into_response()
}

/// 401 with the `WWW-Authenticate` challenge that makes it actionable.
///
/// "Invalid or expired tokens MUST receive a HTTP 401 response" — the status
/// was already right. What was missing is the header: the authorization flow
/// has the client "Extract `resource_metadata` URL from `WWW-Authenticate`" and
/// then fetch that document to find the authorization server. A bare 401 tells
/// a client it needs a token and nothing about where to get one, which is a
/// dead end on the one response whose job is to start the flow.
fn unauthorized(config: &OAuthConfig, message: &str) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": "unauthorized",
            "message": message,
        })),
    )
        .into_response();
    if let Some(challenge) = bearer_challenge(config, None) {
        response.headers_mut().insert(WWW_AUTHENTICATE, challenge);
    }
    response
}

/// 403 for a valid token that is short a scope.
///
/// "When a client makes a request with an access token with insufficient scope
/// during runtime operations, the server SHOULD respond with: `HTTP 403
/// Forbidden` ... `WWW-Authenticate` header with the `Bearer` scheme and
/// additional parameters: `error="insufficient_scope"` ...
/// `scope="required_scope1 required_scope2"` ... `resource_metadata`".
///
/// `error_description` is the optional fourth parameter; it is carried in the
/// JSON body instead, where it cannot break header parsing.
fn insufficient_scope(config: &OAuthConfig, missing: &[String]) -> Response {
    let mut response = (
        StatusCode::FORBIDDEN,
        axum::Json(json!({
            "error": "insufficient_scope",
            "message": format!("Missing required scope(s): {}", missing.join(" ")),
        })),
    )
        .into_response();
    if let Some(challenge) = bearer_challenge(config, Some("insufficient_scope")) {
        response.headers_mut().insert(WWW_AUTHENTICATE, challenge);
    }
    response
}

/// OAuth 2.0 Protected Resource Metadata (RFC 9728).
///
/// Served at `GET /.well-known/oauth-protected-resource`. NOT optional:
/// "MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata
/// (RFC9728). MCP clients **MUST** use OAuth 2.0 Protected Resource Metadata
/// for authorization server discovery."
///
/// It is the second half of the 401: the challenge points here, and this
/// document is where a client learns which authorization server to talk to.
/// Neither half existed before, so an OAuth-protected bridge-mcp could refuse
/// a client without ever telling it how to authenticate.
///
/// Distinct from [`OAuthMetadata`], which is RFC 8414 AUTHORIZATION SERVER
/// metadata — a different document about a different party. This server is the
/// resource server; it is not the authorization server, and the two endpoints
/// answer different questions.
#[derive(Debug, Clone, Serialize)]
pub struct ProtectedResourceMetadata {
    /// The canonical URI identifying this resource. The only REQUIRED field.
    pub resource: String,
    /// Issuer identifiers of the authorization servers that can issue tokens
    /// for this resource.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    /// "The `scopes_supported` field is intended to represent the minimal set
    /// of scopes necessary for basic functionality".
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    /// How a token may be presented. Only the `Authorization` header is
    /// accepted here — "Access tokens MUST NOT be included in the URI query
    /// string".
    pub bearer_methods_supported: Vec<String>,
    /// Human-readable name, for a consent screen.
    pub resource_name: String,
}

impl ProtectedResourceMetadata {
    /// Build the document from the runtime OAuth config.
    ///
    /// `resource` prefers the configured `audience`, because that is already
    /// the canonical URI this server validates tokens against — "MCP servers
    /// MUST validate that access tokens were issued specifically for them as
    /// the intended audience". Publishing anything else here would tell clients
    /// to request a `resource` this server then rejects. It falls back to the
    /// bind URL only when no audience is configured.
    #[must_use]
    pub fn from_config(config: &OAuthConfig, base_url: &str) -> Self {
        Self {
            resource: if config.audience.is_empty() {
                base_url.to_string()
            } else {
                config.audience.clone()
            },
            authorization_servers: if config.issuer.is_empty() {
                Vec::new()
            } else {
                vec![config.issuer.clone()]
            },
            scopes_supported: vec![
                scopes::TOOLS_READ.to_string(),
                scopes::TOOLS_EXECUTE.to_string(),
                scopes::RESOURCES_READ.to_string(),
                scopes::ADMIN.to_string(),
            ],
            bearer_methods_supported: vec!["header".to_string()],
            resource_name: crate::mcp::protocol::SERVER_NAME.to_string(),
        }
    }
}

/// OAuth Authorization Server Metadata (RFC 8414).
///
/// Returned by `GET /.well-known/oauth-authorization-server`.
#[derive(Debug, Clone, Serialize)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
}

impl OAuthMetadata {
    /// Build metadata from an OAuth config.
    #[must_use]
    pub fn from_config(config: &OAuthConfig, base_url: &str) -> Self {
        Self {
            issuer: if config.issuer.is_empty() {
                base_url.to_string()
            } else {
                config.issuer.clone()
            },
            token_endpoint: format!("{base_url}/oauth/token"),
            scopes_supported: vec![
                scopes::TOOLS_READ.to_string(),
                scopes::TOOLS_EXECUTE.to_string(),
                scopes::RESOURCES_READ.to_string(),
                scopes::ADMIN.to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_claims_has_scope() {
        let claims = TokenClaims {
            sub: "user1".to_string(),
            iss: "test".to_string(),
            scopes: vec!["mcp:tools:read".to_string(), "mcp:admin".to_string()],
        };
        assert!(claims.has_scope("mcp:tools:read"));
        assert!(claims.has_scope("mcp:admin"));
        assert!(!claims.has_scope("mcp:tools:execute"));
    }

    #[test]
    fn test_oauth_config_default() {
        let config = OAuthConfig::default();
        assert!(!config.enabled);
        assert!(config.issuer.is_empty());
        assert!(config.required_scopes.is_empty());
    }

    #[test]
    fn test_oauth_metadata_from_config() {
        let config = OAuthConfig {
            enabled: true,
            issuer: "https://auth.example.com".to_string(),
            ..Default::default()
        };
        let metadata = OAuthMetadata::from_config(&config, "https://mcp.example.com");
        assert_eq!(metadata.issuer, "https://auth.example.com");
        assert!(
            metadata
                .grant_types_supported
                .contains(&"client_credentials".to_string())
        );
    }

    #[test]
    fn test_validate_token_invalid_format() {
        let config = OAuthConfig::default();
        let validator = OAuthValidator::new(config);
        let result = validator.validate_token("not-a-jwt");
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod jwt_verification_tests {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::json;

    fn priv_pem() -> &'static str {
        include_str!("../../../tests/fixtures/oauth/test_priv.pem")
    }
    fn pub_pem() -> &'static str {
        include_str!("../../../tests/fixtures/oauth/test_pub.pem")
    }

    fn challenge_config() -> OAuthConfig {
        OAuthConfig {
            enabled: true,
            issuer: "https://auth.example.com".to_string(),
            audience: "https://mcp.example.com/mcp".to_string(),
            jwks_uri: None,
            client_id: "test".to_string(),
            required_scopes: vec!["mcp:tools:execute".to_string(), "mcp:admin".to_string()],
            static_keys: vec![],
            resource_metadata_url: "https://mcp.example.com/.well-known/oauth-protected-resource"
                .to_string(),
        }
    }

    /// The 401 must carry the pointer a client needs to start the flow:
    /// "Extract `resource_metadata` URL from `WWW-Authenticate`".
    #[test]
    fn the_unauthorized_challenge_names_the_metadata_document() {
        let response = unauthorized(&challenge_config(), "no token");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("a 401 must carry a WWW-Authenticate challenge")
            .to_str()
            .unwrap();
        assert!(challenge.starts_with("Bearer "), "{challenge}");
        assert!(
            challenge.contains(
                "resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\""
            ),
            "{challenge}"
        );
        // SHOULD, and it is what lets a client ask for the right scopes the
        // first time instead of discovering them by rejection.
        assert!(
            challenge.contains("scope=\"mcp:tools:execute mcp:admin\""),
            "{challenge}"
        );
        // A 401 is not a scope failure.
        assert!(!challenge.contains("insufficient_scope"), "{challenge}");
    }

    /// A valid token short a scope is 403, not 401. They are different rows in
    /// the error table, and a client that reads 401 re-authenticates with the
    /// same scope set and loops.
    #[test]
    fn an_insufficient_scope_is_403_with_the_error_parameter() {
        let response = insufficient_scope(&challenge_config(), &["mcp:admin".to_string()]);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let challenge = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("a 403 must carry a WWW-Authenticate challenge")
            .to_str()
            .unwrap();
        assert!(
            challenge.contains("error=\"insufficient_scope\""),
            "{challenge}"
        );
        assert!(challenge.contains("scope="), "{challenge}");
        assert!(challenge.contains("resource_metadata="), "{challenge}");
    }

    /// A config with nothing to say still produces a parseable bare challenge
    /// rather than a malformed header or none at all.
    #[test]
    fn an_empty_config_still_yields_a_bare_bearer_challenge() {
        let value = bearer_challenge(&OAuthConfig::default(), None).expect("a challenge");
        assert_eq!(value.to_str().unwrap(), "Bearer");
    }

    /// RFC 9728: `resource` is the only REQUIRED field, and it must be the
    /// audience this server validates tokens against — publishing anything
    /// else would send clients to request a `resource` this server rejects.
    #[test]
    fn the_protected_resource_metadata_publishes_the_validated_audience() {
        let metadata =
            ProtectedResourceMetadata::from_config(&challenge_config(), "http://127.0.0.1:8080");
        assert_eq!(metadata.resource, "https://mcp.example.com/mcp");
        assert_eq!(metadata.authorization_servers, ["https://auth.example.com"]);
        assert_eq!(metadata.bearer_methods_supported, ["header"]);
        assert!(!metadata.scopes_supported.is_empty());
    }

    /// With no audience configured there is still a `resource`, because the
    /// field is REQUIRED and an absent one makes the document invalid.
    #[test]
    fn the_protected_resource_metadata_falls_back_to_the_bind_url() {
        let metadata = ProtectedResourceMetadata::from_config(
            &OAuthConfig::default(),
            "http://127.0.0.1:8080",
        );
        assert_eq!(metadata.resource, "http://127.0.0.1:8080");
        assert!(metadata.authorization_servers.is_empty());
    }

    fn make_validator() -> OAuthValidator {
        let cfg = OAuthConfig {
            resource_metadata_url: String::new(),
            enabled: true,
            issuer: "iss".to_string(),
            audience: "aud".to_string(),
            jwks_uri: None,
            client_id: "test".to_string(),
            required_scopes: vec!["mcp:tools:execute".to_string()],
            static_keys: vec![],
        };
        let mut v = OAuthValidator::new(cfg);
        v.set_static_keys(vec![("kid-test".to_string(), pub_pem().to_string())]);
        v
    }

    fn sign_token(claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("kid-test".to_string());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(priv_pem().as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// EVERY missing scope in one challenge, not the first one found.
    ///
    /// "servers SHOULD include all scopes required for the current operation in
    /// a single challenge. Challenging incrementally (returning one missing
    /// scope, then another on the subsequent retry) forces multiple
    /// authorization round-trips for a single operation and degrades user
    /// experience." The loop here used to `return` on the first miss, which is
    /// precisely the incremental challenge that sentence forbids.
    #[test]
    fn an_insufficient_token_reports_every_missing_scope_at_once() {
        let mut cfg = challenge_config();
        cfg.issuer = "iss".to_string();
        cfg.audience = "aud".to_string();
        cfg.required_scopes = vec![
            "mcp:tools:execute".to_string(),
            "mcp:admin".to_string(),
            "mcp:resources:read".to_string(),
        ];
        let mut v = OAuthValidator::new(cfg);
        v.set_static_keys(vec![("kid-test".to_string(), pub_pem().to_string())]);

        let now = chrono::Utc::now().timestamp();
        let token = sign_token(&serde_json::json!({
            "iss": "iss", "aud": "aud", "sub": "u1",
            "exp": now + 600, "nbf": now - 10,
            // Holds one of the three.
            "scope": "mcp:tools:execute"
        }));

        match v.validate_token(&token) {
            Err(TokenError::InsufficientScope { missing }) => {
                assert_eq!(missing, ["mcp:admin", "mcp:resources:read"], "{missing:?}");
            }
            other => panic!("expected InsufficientScope, got {other:?}"),
        }
    }

    /// A scope failure and a signature failure are different errors, and this
    /// is what lets the middleware answer 403 for one and 401 for the other.
    /// While both were `Err(String)` it could not tell them apart.
    #[test]
    fn a_broken_token_is_invalid_not_an_insufficient_scope() {
        let v = make_validator();
        assert!(matches!(
            v.validate_token("not-a-jwt"),
            Err(TokenError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_token_with_invalid_signature() {
        let v = make_validator();
        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "iss": "iss", "aud": "aud", "scope": "mcp:tools:execute",
            "exp": now + 60, "iat": now, "sub": "alice",
        });
        let valid = sign_token(&claims);
        let mut parts: Vec<String> = valid.split('.').map(String::from).collect();
        parts[2] = "AAAA".to_string();
        let forged = parts.join(".");
        assert!(v.validate_token(&forged).is_err());
    }

    #[test]
    fn rejects_alg_none() {
        let v = make_validator();
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","kid":"kid-test"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"iss":"iss","aud":"aud","scope":"mcp:tools:execute","exp":99999999999}"#);
        let none_token = format!("{header}.{payload}.");
        assert!(v.validate_token(&none_token).is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let v = make_validator();
        let claims = json!({
            "iss": "iss", "aud": "aud", "scope": "mcp:tools:execute",
            "exp": 1_000_000, "iat": 999_000, "sub": "alice",
        });
        let token = sign_token(&claims);
        assert!(v.validate_token(&token).is_err());
    }

    #[test]
    fn rejects_wrong_issuer() {
        let v = make_validator();
        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "iss": "evil", "aud": "aud", "scope": "mcp:tools:execute",
            "exp": now + 60, "iat": now, "sub": "alice",
        });
        let token = sign_token(&claims);
        assert!(v.validate_token(&token).is_err());
    }

    #[test]
    fn rejects_missing_scope() {
        let v = make_validator();
        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "iss": "iss", "aud": "aud", "scope": "mcp:tools:read",
            "exp": now + 60, "iat": now, "sub": "alice",
        });
        let token = sign_token(&claims);
        assert!(v.validate_token(&token).is_err());
    }

    #[test]
    fn accepts_well_formed_token() {
        let v = make_validator();
        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "iss": "iss", "aud": "aud", "scope": "mcp:tools:execute mcp:admin",
            "exp": now + 600, "iat": now, "sub": "alice",
        });
        let token = sign_token(&claims);
        let claims = v.validate_token(&token).expect("valid token");
        assert_eq!(claims.sub, "alice");
        assert!(claims.scopes.iter().any(|s| s == "mcp:tools:execute"));
    }

    #[tokio::test]
    async fn build_validator_static_key_validates_token() {
        use crate::config::types::{HttpOAuthConfig, HttpOAuthStaticKey};

        let cfg = HttpOAuthConfig {
            enabled: true,
            issuer: "iss".into(),
            audience: "aud".into(),
            client_id: "test".into(),
            required_scopes: vec!["mcp:tools:execute".into()],
            jwks_uri: None,
            static_keys: vec![HttpOAuthStaticKey {
                kid: "kid-test".into(),
                public_key_pem: pub_pem().into(),
            }],
        };

        let v = super::build_validator(&cfg)
            .await
            .expect("validator built from static keys");
        assert_eq!(v.key_count(), 1);

        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "iss": "iss", "aud": "aud", "scope": "mcp:tools:execute",
            "exp": now + 600, "iat": now, "sub": "bob",
        });
        let token = sign_token(&claims);
        let parsed = v.validate_token(&token).expect("valid token");
        assert_eq!(parsed.sub, "bob");
    }

    /// Build a JWT claims object with all four required spec claims
    /// (`exp`, `sub`, `iss`, `aud`) populated, then remove the named claim
    /// before signing. Used by the "missing required claim" tests below.
    fn claims_omitting(name: &str) -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "iss": "iss",
            "aud": "aud",
            "scope": "mcp:tools:execute",
            "exp": now + 600,
            "iat": now,
            "sub": "alice",
        });
        claims
            .as_object_mut()
            .expect("claims is an object")
            .remove(name);
        claims
    }

    #[test]
    fn token_missing_sub_is_rejected() {
        let v = make_validator();
        let token = sign_token(&claims_omitting("sub"));
        assert!(
            v.validate_token(&token).is_err(),
            "token without `sub` claim must be rejected"
        );
    }

    #[test]
    fn token_missing_iss_is_rejected() {
        let v = make_validator();
        let token = sign_token(&claims_omitting("iss"));
        assert!(
            v.validate_token(&token).is_err(),
            "token without `iss` claim must be rejected"
        );
    }

    #[test]
    fn token_missing_aud_is_rejected() {
        let v = make_validator();
        let token = sign_token(&claims_omitting("aud"));
        assert!(
            v.validate_token(&token).is_err(),
            "token without `aud` claim must be rejected"
        );
    }

    #[test]
    fn token_missing_exp_is_rejected() {
        let v = make_validator();
        let token = sign_token(&claims_omitting("exp"));
        assert!(
            v.validate_token(&token).is_err(),
            "token without `exp` claim must be rejected"
        );
    }

    #[tokio::test]
    async fn build_validator_rejects_empty_when_enabled() {
        use crate::config::types::HttpOAuthConfig;

        let cfg = HttpOAuthConfig {
            enabled: true,
            issuer: "iss".into(),
            audience: "aud".into(),
            client_id: "test".into(),
            required_scopes: vec![],
            jwks_uri: None,
            static_keys: vec![],
        };
        assert!(super::build_validator(&cfg).await.is_err());
    }
}
