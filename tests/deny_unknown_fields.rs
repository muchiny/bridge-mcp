//! FIND-017: top-level `Config` and nested config structs must reject
//! unknown YAML fields.
//!
//! `serde_saphyr`'s strict typing partially compensates for missing
//! `#[serde(deny_unknown_fields)]` (e.g., it rejects type mismatches),
//! but does not by itself reject extra map keys that happen to be
//! valid YAML strings. Adding `deny_unknown_fields` is belt-and-suspenders
//! against typo'd config keys silently being ignored.

use bridge_mcp::Config;

#[test]
fn unknown_top_level_field_rejected() {
    let yaml = r"
hosts: {}
bogus_field: 1
";
    let r: Result<Config, _> = bridge_mcp::domain::yaml::parse_yaml(yaml);
    assert!(
        r.is_err(),
        "FIND-017: unknown top-level field must be rejected by deny_unknown_fields"
    );
}

#[test]
fn unknown_nested_host_field_rejected() {
    let yaml = r"
hosts:
  prod:
    hostname: example.com
    port: 22
    user: root
    auth:
      type: agent
    bogus_host_field: 1
";
    let r: Result<Config, _> = bridge_mcp::domain::yaml::parse_yaml(yaml);
    assert!(
        r.is_err(),
        "FIND-017: unknown nested field on HostConfig must be rejected"
    );
}

#[test]
fn unknown_nested_security_field_rejected() {
    let yaml = r"
security:
  mode: standard
  bogus_security_field: hello
";
    let r: Result<Config, _> = bridge_mcp::domain::yaml::parse_yaml(yaml);
    assert!(
        r.is_err(),
        "FIND-017: unknown nested field on SecurityConfig must be rejected"
    );
}

#[test]
fn unknown_nested_limits_field_rejected() {
    let yaml = r"
limits:
  command_timeout_seconds: 60
  bogus_limit: 9999
";
    let r: Result<Config, _> = bridge_mcp::domain::yaml::parse_yaml(yaml);
    assert!(
        r.is_err(),
        "FIND-017: unknown nested field on LimitsConfig must be rejected"
    );
}

#[test]
fn unknown_runbook_field_rejected() {
    use bridge_mcp::domain::runbook::Runbook;

    let yaml = r"
name: probe
description: extra field at runbook level
steps:
  - name: noop
    command: echo
unexpected_top_level: 1
";
    let r: Result<Runbook, _> = bridge_mcp::domain::yaml::parse_yaml(yaml);
    assert!(
        r.is_err(),
        "FIND-017: unknown top-level field on Runbook must be rejected"
    );
}

#[test]
fn unknown_runbook_step_field_rejected() {
    use bridge_mcp::domain::runbook::Runbook;

    let yaml = r"
name: probe
description: extra field on a step
steps:
  - name: bad
    command: echo
    bogus_step_field: 1
";
    let r: Result<Runbook, _> = bridge_mcp::domain::yaml::parse_yaml(yaml);
    assert!(
        r.is_err(),
        "FIND-017: unknown nested field on RunbookStep must be rejected"
    );
}

/// Sanity: a known-good config still parses after `deny_unknown_fields`
/// is applied. Acts as a regression guard against accidentally renaming
/// fields without keeping a `#[serde(alias = ...)]` shim.
#[test]
fn known_good_config_still_parses() {
    let yaml = r"
hosts:
  prod:
    hostname: example.com
    port: 22
    user: root
    auth:
      type: agent
limits:
  command_timeout_seconds: 60
security:
  mode: standard
";
    let r: Result<Config, _> = bridge_mcp::domain::yaml::parse_yaml(yaml);
    assert!(
        r.is_ok(),
        "FIND-017: known-good config must still parse: {:?}",
        r.err()
    );
}
