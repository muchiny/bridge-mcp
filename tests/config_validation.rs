//! Config Validation Integration Tests
//!
//! Tests for configuration loading from real YAML files, validation edge cases,
//! and default value preservation. Complements unit tests in `src/config/loader.rs`.

use std::io::Write;
use std::path::Path;

use bridge_mcp::config::{Config, HostKeyVerification, OsType};
use bridge_mcp::error::BridgeError;

/// Load config from a YAML string via a temp file with secure permissions
fn load_yaml(yaml: &str) -> Result<Config, BridgeError> {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(yaml.as_bytes()).unwrap();
    file.flush().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    bridge_mcp::config::load_config(file.path())
}

// ============== File Handling ==============

#[test]
fn test_load_config_missing_file() {
    let result = bridge_mcp::config::load_config(Path::new("/nonexistent/path/config.yaml"));
    assert!(matches!(result, Err(BridgeError::ConfigNotFound { .. })));
}

#[test]
fn test_load_config_empty_file() {
    let result = load_yaml("");
    assert!(result.is_err(), "Empty file should fail to load");
}

#[test]
fn test_load_config_invalid_yaml_syntax() {
    let result = load_yaml("[unclosed bracket");
    assert!(result.is_err(), "Invalid YAML should fail to parse");
}

#[test]
fn test_load_config_yaml_with_only_comments() {
    let result = load_yaml("# This is only comments\n# No actual config\n");
    assert!(result.is_err(), "YAML with only comments should fail");
}

// ============== Host Validation ==============

#[test]
fn test_validate_no_hosts_rejected() {
    let result = load_yaml(
        r"
hosts: {}
security:
  mode: permissive
",
    );
    assert!(matches!(result, Err(BridgeError::ConfigInvalid { field, .. }) if field == "hosts"));
}

#[test]
fn test_validate_empty_hostname_rejected() {
    let result = load_yaml(
        r#"
hosts:
  test:
    hostname: ""
    user: admin
    auth:
      type: agent
"#,
    );
    assert!(
        matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("hostname") && reason.contains("empty"))
    );
}

#[test]
fn test_validate_empty_user_rejected() {
    let result = load_yaml(
        r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: ""
    auth:
      type: agent
"#,
    );
    assert!(
        matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("user") && reason.contains("empty"))
    );
}

#[test]
fn test_validate_proxy_jump_and_socks_mutually_exclusive() {
    let result = load_yaml(
        r#"
hosts:
  conflict:
    hostname: "10.0.0.1"
    user: admin
    auth:
      type: agent
    proxy_jump: bastion
    socks_proxy:
      hostname: proxy.corp.com
"#,
    );
    assert!(
        matches!(result, Err(BridgeError::ConfigInvalid { reason, .. })
            if reason.contains("mutually exclusive"))
    );
}

// ============== Regex Validation ==============

#[test]
fn test_validate_invalid_whitelist_regex() {
    let result = load_yaml(
        r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: admin
    auth:
      type: agent
security:
  mode: strict
  whitelist:
    - "[invalid(regex"
"#,
    );
    assert!(
        matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("whitelist") && reason.contains("Invalid regex"))
    );
}

#[test]
fn test_validate_invalid_blacklist_regex() {
    let result = load_yaml(
        r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: admin
    auth:
      type: agent
security:
  mode: permissive
  blacklist:
    - "(unclosed"
"#,
    );
    assert!(
        matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("blacklist") && reason.contains("Invalid regex"))
    );
}

#[test]
fn test_validate_invalid_sanitize_pattern_regex() {
    let result = load_yaml(
        r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: admin
    auth:
      type: agent
security:
  sanitize_patterns:
    - "(unmatched"
"#,
    );
    assert!(
        matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("sanitize_patterns") && reason.contains("Invalid regex"))
    );
}

// ============== Valid Configurations ==============

#[test]
fn test_valid_minimal_config_with_agent_auth() {
    let config = load_yaml(
        r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: admin
    auth:
      type: agent
security:
  mode: permissive
"#,
    )
    .unwrap();

    assert!(config.hosts.contains_key("test"));
    assert_eq!(config.hosts["test"].hostname, "10.0.0.1");
    assert_eq!(config.hosts["test"].user, "admin");
}

#[test]
fn test_valid_config_preserves_defaults() {
    let config = load_yaml(
        r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: admin
    auth:
      type: agent
"#,
    )
    .unwrap();

    // Port defaults to 22
    assert_eq!(config.hosts["test"].port, 22);

    // Host key verification defaults to Strict
    assert_eq!(
        config.hosts["test"].host_key_verification,
        HostKeyVerification::Strict
    );

    // OS type defaults to Linux
    assert_eq!(config.hosts["test"].os_type, OsType::Linux);

    // Limits have reasonable defaults
    assert!(config.limits.command_timeout_seconds > 0);
    assert!(config.limits.max_output_bytes > 0);
    assert!(config.limits.max_concurrent_commands > 0);

    // FIND-023 (audit 2026-05-09): SSH config discovery is now opt-in.
    // Operators must set `ssh_config.enabled: true` to scan ~/.ssh/config.
    assert!(!config.ssh_config.enabled);
}

#[test]
fn test_valid_config_with_multiple_hosts() {
    let config = load_yaml(
        r#"
hosts:
  web:
    hostname: "10.0.0.1"
    user: deploy
    auth:
      type: agent
  db:
    hostname: "10.0.0.2"
    user: dba
    port: 2222
    auth:
      type: agent
  bastion:
    hostname: "bastion.example.com"
    user: admin
    auth:
      type: agent
security:
  mode: permissive
"#,
    )
    .unwrap();

    assert_eq!(config.hosts.len(), 3);
    assert_eq!(config.hosts["db"].port, 2222);
    assert_eq!(config.hosts["bastion"].hostname, "bastion.example.com");
}

#[test]
fn test_valid_config_with_windows_host() {
    let config = load_yaml(
        r#"
hosts:
  winserver:
    hostname: "10.0.0.50"
    user: Administrator
    auth:
      type: agent
    os_type: windows
    shell: powershell
security:
  mode: permissive
"#,
    )
    .unwrap();

    assert_eq!(config.hosts["winserver"].os_type, OsType::Windows);
}

#[test]
fn test_valid_config_with_all_security_options() {
    let config = load_yaml(
        r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: admin
    auth:
      type: agent
security:
  mode: strict
  whitelist:
    - "^ls\\b"
    - "^cat\\b"
  blacklist:
    - "rm\\s+-rf"
  sanitize_patterns:
    - "password=\\S+"
"#,
    )
    .unwrap();

    assert_eq!(config.security.whitelist.len(), 2);
    assert_eq!(config.security.blacklist.len(), 1);
    assert_eq!(config.security.sanitize_patterns.len(), 1);
}

#[test]
fn test_valid_config_with_tool_groups() {
    let config = load_yaml(
        r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: admin
    auth:
      type: agent
tool_groups:
  groups:
    docker: false
    kubernetes: false
    ansible: false
security:
  mode: permissive
"#,
    )
    .unwrap();

    assert!(!config.tool_groups.is_group_enabled("docker"));
    assert!(!config.tool_groups.is_group_enabled("kubernetes"));
    assert!(!config.tool_groups.is_group_enabled("ansible"));
    assert!(config.tool_groups.is_group_enabled("core")); // Unlisted = enabled
}
