//! FIND-006: OAuth feature must validate tokens against keys loaded at boot,
//! not against a per-request empty key map.

#![cfg(feature = "http")]

use mcp_ssh_bridge::config::types::{HttpOAuthConfig, HttpOAuthStaticKey};
use mcp_ssh_bridge::mcp::transport::oauth::build_validator;

#[tokio::test]
async fn empty_key_config_fails_closed_at_boot() {
    let cfg = HttpOAuthConfig {
        enabled: true,
        issuer: "https://example.com".into(),
        audience: "test-aud".into(),
        client_id: "test".into(),
        required_scopes: vec![],
        jwks_uri: None,
        static_keys: vec![],
    };
    let result = build_validator(&cfg).await;
    assert!(
        result.is_err(),
        "build_validator MUST fail when oauth.enabled=true but no keys are configured"
    );
}

#[tokio::test]
async fn jwks_uri_without_static_keys_is_deferred() {
    // JWKS fetching is deferred to a follow-up; until reqwest is wired
    // through extensions we expect a clear error rather than a silent
    // empty-key validator.
    let cfg = HttpOAuthConfig {
        enabled: true,
        issuer: "https://example.com".into(),
        audience: "test-aud".into(),
        client_id: "test".into(),
        required_scopes: vec![],
        jwks_uri: Some("https://example.com/jwks.json".into()),
        static_keys: vec![],
    };
    let result = build_validator(&cfg).await;
    assert!(
        result.is_err(),
        "build_validator MUST fail when only jwks_uri is configured (fetch not yet wired)"
    );
}

#[tokio::test]
async fn validator_built_with_static_key_loads_key() {
    let pub_pem = include_str!("fixtures/oauth/test_pub.pem");
    let cfg = HttpOAuthConfig {
        enabled: true,
        issuer: "iss".into(),
        audience: "aud".into(),
        client_id: "test".into(),
        required_scopes: vec![],
        jwks_uri: None,
        static_keys: vec![HttpOAuthStaticKey {
            kid: "kid-test".into(),
            public_key_pem: pub_pem.into(),
        }],
    };
    let v = build_validator(&cfg)
        .await
        .expect("validator built with static key");
    assert_eq!(v.key_count(), 1, "static key should be loaded");
}
