//! FIND-022: destructive elicitation gate must default ON.
//!
//! Regression test: ensure `SecurityConfig::default()` returns
//! `require_elicitation_on_destructive: true` so that destructive tools
//! require MCP `elicitation/create` confirmation by default. Operators who
//! want the legacy permissive behaviour must opt out explicitly via
//! `security.require_elicitation_on_destructive: false` in config.

use mcp_ssh_bridge::config::types::SecurityConfig;

#[test]
fn destructive_elicitation_default_is_true() {
    let cfg = SecurityConfig::default();
    assert!(
        cfg.require_elicitation_on_destructive,
        "FIND-022: gate must be ON by default"
    );
}
