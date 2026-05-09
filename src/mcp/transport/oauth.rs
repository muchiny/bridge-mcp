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
//! [`OAuthValidator`] from a [`HttpOAuthConfig`]. The validator pre-loads
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
use axum::http::StatusCode;
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
///   [`Self::refresh_jwks`])
pub struct OAuthValidator {
    config: OAuthConfig,
    /// Public keys keyed by `kid`. Each value is either a PEM blob or the
    /// `n.e` JWK components when populated by [`Self::refresh_jwks`].
    keys: HashMap<String, String>,
}

impl OAuthValidator {
    /// Create a new OAuth validator with no signing keys.
    ///
    /// Callers must populate keys via [`Self::set_static_keys`] or
    /// [`Self::refresh_jwks`] before any token will be accepted.
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
    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, String> {
        // Decode the unverified header to learn the algorithm and key id.
        let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {e}"))?;

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
            other => return Err(format!("Algorithm '{other:?}' not accepted")),
        }

        let kid = header
            .kid
            .ok_or_else(|| "JWT missing kid header".to_string())?;
        let key_material = self
            .keys
            .get(&kid)
            .ok_or_else(|| format!("Unknown JWT signing key: {kid}"))?;

        let decoding_key = if let Some((n, e)) = key_material.split_once('.') {
            DecodingKey::from_rsa_components(n, e)
                .map_err(|err| format!("Invalid JWKS RSA components: {err}"))?
        } else {
            DecodingKey::from_rsa_pem(key_material.as_bytes())
                .map_err(|err| format!("Invalid PEM signing key: {err}"))?
        };

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 30;

        let data = decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| format!("JWT validation failed: {e}"))?;

        let scopes: Vec<String> = data
            .claims
            .scope
            .split_whitespace()
            .map(String::from)
            .collect();

        for required in &self.config.required_scopes {
            if !scopes.iter().any(|s| s == required) {
                return Err(format!("Missing required scope: {required}"));
            }
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
pub async fn build_validator_from_runtime(
    cfg: &OAuthConfig,
) -> Result<OAuthValidator, String> {
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
        return unauthorized("Missing Authorization header");
    };

    let Some(token) = auth.strip_prefix("Bearer ") else {
        return unauthorized("Invalid Authorization scheme, expected Bearer");
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
        Err(e) => {
            warn!(error = %e, "Token validation failed");
            unauthorized(&e)
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

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": "unauthorized",
            "message": message,
        })),
    )
        .into_response()
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

    fn make_validator() -> OAuthValidator {
        let cfg = OAuthConfig {
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

    fn sign_token(claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("kid-test".to_string());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(priv_pem().as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn rejects_token_with_invalid_signature() {
        let v = make_validator();
        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "iss": "iss", "aud": "aud", "scope": "mcp:tools:execute",
            "exp": now + 60, "iat": now, "sub": "alice",
        });
        let valid = sign_token(claims);
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
        let token = sign_token(claims);
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
        let token = sign_token(claims);
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
        let token = sign_token(claims);
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
        let token = sign_token(claims);
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
        let token = sign_token(claims);
        let parsed = v.validate_token(&token).expect("valid token");
        assert_eq!(parsed.sub, "bob");
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
