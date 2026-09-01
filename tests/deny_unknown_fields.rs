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

/// `AuthConfig` is internally tagged, and serde IGNORES unknown fields on an
/// internally-tagged enum unless told otherwise. Every other struct in the
/// config refused the unknown; this one swallowed it, so a misspelt
/// `passphrase` loaded in silence and surfaced later as `SshKeyInvalid`,
/// which accuses the key file rather than the typo.
#[test]
fn unknown_auth_field_rejected() {
    let yaml = r"
hosts:
  prod:
    hostname: example.com
    user: root
    auth:
      type: key
      path: /home/me/.ssh/id_ed25519
      passphraze: hunter2
";
    let r: Result<Config, _> = bridge_mcp::domain::yaml::parse_yaml(yaml);
    let err = r.expect_err("a misspelt auth key must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("passphraze"),
        "the message must name the offending key, got: {msg}"
    );
}

/// The guard must not cost the shapes people actually write.
#[test]
fn well_formed_auth_blocks_still_parse() {
    let yaml = r"
hosts:
  by_key:
    hostname: a.example.com
    user: root
    auth:
      type: key
      path: /home/me/.ssh/id_ed25519
  by_agent:
    hostname: b.example.com
    user: root
    auth:
      type: agent
  by_password:
    hostname: c.example.com
    user: root
    auth:
      type: password
      password: hunter2
";
    bridge_mcp::domain::yaml::parse_yaml::<Config>(yaml).expect("every auth variant must parse");
}

/// A parse error must not recite the file back.
///
/// saphyr renders three source lines around the fault, rustc-style. In a
/// config file, a `password:` is within three lines of almost any mistake, and
/// that message goes to stderr — at startup, and on every failed hot-reload —
/// where the MCP client keeps its log. The Sanitizer cannot help: it masks
/// `known_secrets` gathered from a config that LOADED, which is exactly what
/// does not exist when parsing failed.
#[test]
fn a_parse_error_does_not_echo_a_neighbouring_secret() {
    let yaml = r"
hosts:
  prod:
    hostname: example.com
    user: root
    auth:
      type: password
      password: SUPER-SECRET-CANARY
    bogus_key: 1
";
    let msg = bridge_mcp::domain::yaml::parse_yaml::<Config>(yaml)
        .expect_err("bogus_key must be refused")
        .to_string();

    assert!(
        !msg.contains("SUPER-SECRET-CANARY"),
        "the parse error recited the password: {msg}"
    );
    // Still useful, though: the operator needs to find the mistake.
    assert!(msg.contains("bogus_key"), "must name the field: {msg}");
    assert!(msg.contains("line 9"), "must give the position: {msg}");
}
