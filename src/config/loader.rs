use super::ssh_config;
use super::types::Config;
use crate::error::{BridgeError, Result};
use std::path::Path;
use tracing::{debug, info, warn};

/// Load configuration from a YAML file
///
/// # Errors
///
/// Returns an error if:
/// - The configuration file does not exist
/// - The file cannot be read
/// - The YAML content is invalid or cannot be parsed
/// - The configuration fails validation (e.g., no hosts defined, invalid regex patterns)
pub fn load_config(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Err(BridgeError::ConfigNotFound {
            path: path.display().to_string(),
        });
    }

    // Reject config file with overly permissive permissions (may contain secrets)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.mode() & 0o777;
            if mode & 0o037 != 0 {
                return Err(BridgeError::ConfigInvalid {
                    field: "file_permissions".to_string(),
                    reason: format!(
                        "Config file '{}' has permissions {mode:04o}; \
                         expected no group-write/other access (max 0640). \
                         Fix with: chmod 640 {}",
                        path.display(),
                        path.display()
                    ),
                });
            }
        }
    }

    let content = std::fs::read_to_string(path)?;
    let mut config: Config = crate::domain::yaml::parse_yaml(&content)?;

    normalize_paths(&mut config);

    // Merge hosts from ~/.ssh/config if discovery is enabled
    if config.ssh_config.enabled {
        merge_ssh_config_hosts(&mut config);
    }

    validate_config(&config)?;

    Ok(config)
}

/// Expand a leading `~` in path-typed config fields so a value like
/// `audit.path: ~/.local/share/bridge-mcp/audit.log` resolves to the
/// user's home directory instead of a literal `~` directory under the
/// server's working directory. SSH key and `ssh_config` paths are already
/// expanded on use in `validate_config`/`merge_ssh_config_hosts`; this
/// covers `PathBuf` fields opened directly (currently `audit.path`).
fn normalize_paths(config: &mut Config) {
    if let Some(p) = config.audit.path.to_str() {
        config.audit.path =
            crate::path_utils::home_expand(p).unwrap_or_else(|| config.audit.path.clone());
    }
}

/// Discover hosts from SSH config and merge into the main config.
/// YAML-defined hosts take precedence over discovered ones.
fn merge_ssh_config_hosts(config: &mut Config) {
    let ssh_config_path = crate::path_utils::home_expand_or_input(&config.ssh_config.path);
    let path = Path::new(&ssh_config_path);

    if !path.exists() {
        debug!(path = %ssh_config_path, "SSH config file not found, skipping discovery");
        return;
    }

    match ssh_config::parse_ssh_config(path, &config.ssh_config.exclude) {
        Ok(discovered) => {
            let count = discovered.len();
            for (alias, host_config) in discovered {
                // YAML takes precedence: only insert if not already defined
                use std::collections::hash_map::Entry;
                match config.hosts.entry(alias) {
                    Entry::Vacant(entry) => {
                        entry.insert(host_config);
                    }
                    Entry::Occupied(entry) => {
                        debug!(host = %entry.key(), "SSH config host skipped (already defined in YAML)");
                    }
                }
            }
            info!(count, "Discovered hosts from SSH config");
        }
        Err(e) => {
            warn!(error = %e, path = %ssh_config_path, "Failed to parse SSH config");
        }
    }
}

/// Validate the configuration
fn validate_config(config: &Config) -> Result<()> {
    // Must have at least one host
    if config.hosts.is_empty() {
        return Err(BridgeError::ConfigInvalid {
            field: "hosts".to_string(),
            reason: "At least one host must be defined".to_string(),
        });
    }

    // Validate each host
    for (name, host) in &config.hosts {
        // Validate hostname
        if host.hostname.is_empty() {
            return Err(BridgeError::ConfigInvalid {
                field: format!("hosts.{name}.hostname"),
                reason: "Hostname cannot be empty".to_string(),
            });
        }

        // Validate user
        if host.user.is_empty() {
            return Err(BridgeError::ConfigInvalid {
                field: format!("hosts.{name}.user"),
                reason: "User cannot be empty".to_string(),
            });
        }

        // Validate proxy_jump and socks_proxy are mutually exclusive
        if host.proxy_jump.is_some() && host.socks_proxy.is_some() {
            return Err(BridgeError::ConfigInvalid {
                field: format!("hosts.{name}"),
                reason: "proxy_jump and socks_proxy are mutually exclusive".to_string(),
            });
        }

        // Reject SSH-only auth types for WinRM/PSRP protocols
        #[cfg(any(feature = "winrm", feature = "psrp"))]
        validate_protocol_auth_compat(name, host)?;

        // Reject proxy_jump for WinRM/PSRP protocols
        #[cfg(any(feature = "winrm", feature = "psrp"))]
        if host.proxy_jump.is_some() && protocol_is_winrm_like(host) {
            return Err(BridgeError::ConfigInvalid {
                field: format!("hosts.{name}.proxy_jump"),
                reason: "proxy_jump (SSH jump hosts) is not supported for WinRM/PSRP \
                         protocols; use a network-level proxy instead"
                    .to_string(),
            });
        }

        // Warn about Basic auth over plain HTTP (credentials exposed)
        #[cfg(feature = "winrm")]
        if protocol_is_winrm_like(host)
            && matches!(host.auth, super::types::AuthConfig::Password { .. })
            && !host.winrm_use_tls.unwrap_or(host.port == 5986)
        {
            warn!(
                host = %name,
                "WinRM Basic auth over plain HTTP exposes credentials in cleartext; \
                 set winrm_use_tls: true or use NTLM/Kerberos auth"
            );
        }

        // Validate key path exists and permissions (for key auth)
        if let super::types::AuthConfig::Key { path, .. } = &host.auth {
            let expanded = crate::path_utils::home_expand_or_input(path);
            let key_path = Path::new(&expanded);
            if !key_path.exists() {
                return Err(BridgeError::SshKeyNotFound { path: path.clone() });
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(metadata) = std::fs::metadata(key_path) {
                    let mode = metadata.mode() & 0o777;
                    if mode & 0o077 != 0 {
                        return Err(BridgeError::ConfigInvalid {
                            field: format!("hosts.{name}.auth.path"),
                            reason: format!(
                                "SSH key file '{path}' has permissions {mode:04o}; expected 0600. \
                                 Fix with: chmod 600 {path}"
                            ),
                        });
                    }
                }
            }
        }
    }

    // Validate regex patterns
    for pattern in &config.security.whitelist {
        regex::Regex::new(pattern).map_err(|e| BridgeError::ConfigInvalid {
            field: "security.whitelist".to_string(),
            reason: format!("Invalid regex '{pattern}': {e}"),
        })?;
    }

    for pattern in &config.security.blacklist {
        regex::Regex::new(pattern).map_err(|e| BridgeError::ConfigInvalid {
            field: "security.blacklist".to_string(),
            reason: format!("Invalid regex '{pattern}': {e}"),
        })?;
    }

    for pattern in &config.security.sanitize_patterns {
        regex::Regex::new(pattern).map_err(|e| BridgeError::ConfigInvalid {
            field: "security.sanitize_patterns".to_string(),
            reason: format!("Invalid regex '{pattern}': {e}"),
        })?;
    }

    reject_settings_that_govern_nothing(config)?;

    Ok(())
}

/// Refuse settings the operator would believe are in force when they are not.
///
/// One rule, three keys, and the rule is what holds them together: each of
/// these parses, validates, and then governs NOTHING. The failure mode is
/// never the wasted field — it is the operator who reads their own config,
/// sees a limit or an access control, and stops looking for a real one.
/// Refusing to start says so once; ignoring the key says nothing, forever.
///
/// `rbac.enabled` is the security case. `RbacConfig` parses into a fully-formed
/// `RbacEnforcer` implementing deny-over-allow — and nothing in the request
/// path ever calls `is_allowed`. There is no principal to check against:
/// neither `ToolContext`, `SessionContext` nor `Session` carries a subject, and
/// the one transport that authenticates discards its claims
/// (`src/mcp/transport/oauth.rs`). Accepting `true` hands over an access
/// control that grants everything.
///
/// `http.session_timeout_seconds` and `http.max_sessions` governed the
/// `Mcp-Session-Id` lifecycle that 3.0.0 deleted along with the rest of the
/// HTTP session machinery: the transport is stateless now. They were still
/// parsed, still plumbed into `mcp::transport::http::HttpTransportConfig`, and
/// read by nothing. This is the exact shape 2.2.0's CHANGELOG called out for
/// `audit.retain_days` — documented in every release and executed in none.
fn reject_settings_that_govern_nothing(config: &Config) -> Result<()> {
    if config.rbac.enabled {
        return Err(BridgeError::ConfigInvalid {
            field: "rbac.enabled".to_string(),
            reason: "security.rbac is not enforced by this build: `rbac.enabled: true` \
                     would grant unrestricted access. Set it to false and restrict access \
                     with `tool_groups.groups` (unlisted groups are already disabled), \
                     `security.mode` + whitelist/blacklist, or per-host configuration."
                .to_string(),
        });
    }

    if config.http.session_timeout_seconds.is_some() {
        return Err(BridgeError::ConfigInvalid {
            field: "http.session_timeout_seconds".to_string(),
            reason: "the HTTP session lifecycle was removed in 3.0.0 — the transport is \
                     stateless and there is no session to expire, so this key has no \
                     effect. Remove it. Per-request duration is bounded by \
                     `limits.command_timeout_seconds` and a tool's own \
                     `timeout_seconds` argument."
                .to_string(),
        });
    }

    if config.http.max_sessions.is_some() {
        return Err(BridgeError::ConfigInvalid {
            field: "http.max_sessions".to_string(),
            reason: "the HTTP session lifecycle was removed in 3.0.0 — the transport is \
                     stateless and holds no session map, so this key caps nothing. Remove \
                     it. To bound concurrent work use `limits.max_concurrent_commands`; \
                     note that `sessions.max_sessions` is a different setting and still \
                     applies, to the SSH connection pool."
                .to_string(),
        });
    }

    Ok(())
}

/// Returns `true` when the host protocol is `WinRM` or `PSRP`.
///
/// Used to guard validations that only apply to the WS-Management protocol
/// family, without resorting to `#[cfg]`-gated `matches!` patterns.
#[cfg(any(feature = "winrm", feature = "psrp"))]
fn protocol_is_winrm_like(host: &super::types::HostConfig) -> bool {
    #[allow(unused_mut)]
    let mut winrm_like = false;
    #[cfg(feature = "winrm")]
    {
        winrm_like |= host.protocol == super::types::Protocol::WinRm;
    }
    #[cfg(feature = "psrp")]
    {
        winrm_like |= host.protocol == super::types::Protocol::Psrp;
    }
    winrm_like
}

/// Validate that the authentication method is compatible with the selected protocol.
///
/// `AuthConfig::Key` and `AuthConfig::Agent` are SSH-only; they cannot be used
/// with `WinRM` or `PSRP` protocols. Returns `BridgeError::ConfigInvalid` when
/// an incompatible combination is detected.
#[cfg(any(feature = "winrm", feature = "psrp"))]
fn validate_protocol_auth_compat(name: &str, host: &super::types::HostConfig) -> Result<()> {
    if !protocol_is_winrm_like(host) {
        return Ok(());
    }

    match &host.auth {
        super::types::AuthConfig::Key { .. } => Err(BridgeError::ConfigInvalid {
            field: format!("hosts.{name}.auth"),
            reason: "SSH key authentication is not supported for WinRM/PSRP protocols; \
                     use password, ntlm, certificate, or kerberos auth instead"
                .to_string(),
        }),
        super::types::AuthConfig::Agent => Err(BridgeError::ConfigInvalid {
            field: format!("hosts.{name}.auth"),
            reason: "SSH agent authentication is not supported for WinRM/PSRP protocols; \
                     use password, ntlm, certificate, or kerberos auth instead"
                .to_string(),
        }),
        _ => Ok(()),
    }
}

/// Get the default config path.
///
/// Prefers the current `bridge-mcp` config directory. For backward
/// compatibility, falls back to the legacy `mcp-ssh-bridge` directory when the
/// new path is absent but the legacy one exists (soft migration after the
/// rename).
#[must_use]
pub fn default_config_path() -> std::path::PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let current = base.join("bridge-mcp").join("config.yaml");
    if !current.exists() {
        let legacy = base.join("mcp-ssh-bridge").join("config.yaml");
        if legacy.exists() {
            return legacy;
        }
    }
    current
}

#[cfg(test)]
#[allow(clippy::needless_raw_string_hashes)]
mod tests {
    use super::*;
    use crate::config::HostKeyVerification;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// Create a `NamedTempFile` with secure permissions (0o600) for config tests.
    #[cfg(unix)]
    fn secure_temp_file() -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        file
    }

    #[cfg(not(unix))]
    fn secure_temp_file() -> NamedTempFile {
        NamedTempFile::new().unwrap()
    }

    #[test]
    fn test_config_not_found() {
        let result = load_config(Path::new("/nonexistent/config.yaml"));
        assert!(matches!(result, Err(BridgeError::ConfigNotFound { .. })));
    }

    #[test]
    fn test_default_config_path() {
        let path = default_config_path();
        assert!(path.ends_with("config.yaml"));
        // Default is the `bridge-mcp` dir; a legacy `mcp-ssh-bridge` config may
        // be returned by the backward-compat fallback when present.
        let s = path.to_string_lossy();
        assert!(s.contains("bridge-mcp") || s.contains("mcp-ssh-bridge"));
    }

    #[test]
    #[cfg(unix)]
    fn test_audit_path_tilde_is_expanded() {
        let yaml = r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: testuser
    auth:
      type: agent
security:
  mode: permissive
audit:
  enabled: true
  path: ~/.local/share/bridge-mcp/audit.log
"#;
        let file = secure_temp_file();
        std::fs::write(file.path(), yaml).unwrap();

        let config = load_config(file.path()).expect("config should load");
        let audit_path = config.audit.path.to_string_lossy();
        assert!(
            !audit_path.starts_with('~') && !audit_path.contains("/~/"),
            "leading ~ in audit.path must be expanded to $HOME, got: {audit_path}"
        );
        if let Some(home) = dirs::home_dir() {
            assert!(
                config.audit.path.starts_with(&home),
                "expanded audit.path should live under $HOME ({}), got: {audit_path}",
                home.display()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_audit_path_absolute_is_unchanged() {
        let yaml = r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: testuser
    auth:
      type: agent
security:
  mode: permissive
audit:
  enabled: true
  path: /var/log/bridge-mcp/audit.log
"#;
        let file = secure_temp_file();
        std::fs::write(file.path(), yaml).unwrap();

        let config = load_config(file.path()).expect("config should load");
        assert_eq!(
            config.audit.path,
            Path::new("/var/log/bridge-mcp/audit.log"),
            "absolute audit.path must pass through unchanged"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_permissive_config_permissions_rejected() {
        let yaml = r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: testuser
    auth:
      type: agent
security:
  mode: permissive
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();
        // Set world-readable permissions
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = load_config(file.path());
        assert!(
            matches!(result, Err(BridgeError::ConfigInvalid { field, .. }) if field == "file_permissions"),
            "Config with world-readable permissions should be rejected"
        );
    }

    #[test]
    fn test_empty_hosts_rejected() {
        let yaml = r#"
hosts: {}
security:
  mode: permissive
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(
            matches!(result, Err(BridgeError::ConfigInvalid { field, .. }) if field == "hosts")
        );
    }

    #[test]
    fn test_empty_hostname_rejected() {
        let yaml = r#"
hosts:
  test:
    hostname: ""
    user: testuser
    auth:
      type: agent
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(
            matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("hostname") && reason.contains("empty"))
        );
    }

    #[test]
    fn test_empty_user_rejected() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: ""
    auth:
      type: agent
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(
            matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("user") && reason.contains("empty"))
        );
    }

    #[test]
    fn test_invalid_whitelist_regex_rejected() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: agent
security:
  mode: strict
  whitelist:
    - "^valid$"
    - "[invalid(regex"
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(
            matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("whitelist") && reason.contains("Invalid regex"))
        );
    }

    #[test]
    fn test_invalid_blacklist_regex_rejected() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: agent
security:
  mode: permissive
  blacklist:
    - "[unclosed"
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(
            matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("blacklist") && reason.contains("Invalid regex"))
        );
    }

    #[test]
    fn test_invalid_sanitize_pattern_rejected() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: agent
security:
  sanitize_patterns:
    - "(unmatched"
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(
            matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("sanitize_patterns") && reason.contains("Invalid regex"))
        );
    }

    #[test]
    fn test_ssh_key_not_found() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: key
      path: /nonexistent/path/to/key
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(matches!(result, Err(BridgeError::SshKeyNotFound { .. })));
    }

    #[test]
    fn test_valid_config_with_agent_auth() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: agent
security:
  mode: permissive
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(config.hosts.contains_key("test"));
    }

    #[test]
    fn test_valid_config_with_password_auth() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: password
      password: "secret123"
security:
  mode: permissive
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_with_all_security_options() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: agent
security:
  mode: strict
  whitelist:
    - "^ls$"
    - "^pwd$"
  blacklist:
    - "rm\\s+-rf"
  sanitize_patterns:
    - "password=\\S+"
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.security.whitelist.len(), 2);
        assert_eq!(config.security.blacklist.len(), 1);
        assert_eq!(config.security.sanitize_patterns.len(), 1);
    }

    #[test]
    fn test_config_with_limits() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: agent
limits:
  command_timeout_seconds: 60
  max_output_bytes: 1048576
  max_concurrent_commands: 10
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.limits.command_timeout_seconds, 60);
        assert_eq!(config.limits.max_output_bytes, 1_048_576);
        assert_eq!(config.limits.max_concurrent_commands, 10);
    }

    #[test]
    fn test_config_with_host_key_verification() {
        let yaml = r#"
hosts:
  strict_host:
    hostname: "192.168.1.1"
    user: testuser
    host_key_verification: strict
    auth:
      type: agent
  acceptnew_host:
    hostname: "192.168.1.2"
    user: testuser
    host_key_verification: acceptnew
    auth:
      type: agent
  off_host:
    hostname: "192.168.1.3"
    user: testuser
    host_key_verification: "off"
    auth:
      type: agent
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
        let config = result.unwrap();

        assert_eq!(
            config.hosts["strict_host"].host_key_verification,
            HostKeyVerification::Strict
        );
        assert_eq!(
            config.hosts["acceptnew_host"].host_key_verification,
            HostKeyVerification::AcceptNew
        );
        assert_eq!(
            config.hosts["off_host"].host_key_verification,
            HostKeyVerification::Off
        );
    }

    #[test]
    fn test_config_with_proxy_jump() {
        let yaml = r#"
hosts:
  bastion:
    hostname: "bastion.example.com"
    user: admin
    auth:
      type: agent
  internal:
    hostname: "internal.example.com"
    user: app
    proxy_jump: bastion
    auth:
      type: agent
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(
            config.hosts["internal"].proxy_jump,
            Some("bastion".to_string())
        );
        assert!(config.hosts["bastion"].proxy_jump.is_none());
    }

    #[test]
    fn test_invalid_yaml_syntax() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: [invalid yaml here
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_config_with_sessions() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: agent
sessions:
  max_sessions: 20
  idle_timeout_seconds: 600
  max_age_seconds: 7200
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.sessions.max_sessions, 20);
        assert_eq!(config.sessions.idle_timeout_seconds, 600);
        assert_eq!(config.sessions.max_age_seconds, 7200);
    }

    #[test]
    fn test_config_with_audit() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: agent
audit:
  enabled: true
  max_size_mb: 50
  retain_days: 7
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(config.audit.enabled);
        assert_eq!(config.audit.max_size_mb, 50);
        assert_eq!(config.audit.retain_days, 7);
    }

    #[test]
    fn test_config_with_sanitize_config() {
        let yaml = r#"
hosts:
  test:
    hostname: "192.168.1.1"
    user: testuser
    auth:
      type: agent
security:
  mode: permissive
  sanitize:
    enabled: true
    disable_builtin:
      - github
      - aws
    custom_patterns:
      - pattern: "my_secret_\\w+"
        replacement: "[MY_SECRET]"
        description: "Custom secret pattern"
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(config.security.sanitize.enabled);
        assert_eq!(config.security.sanitize.disable_builtin.len(), 2);
        assert_eq!(config.security.sanitize.custom_patterns.len(), 1);
        assert_eq!(
            config.security.sanitize.custom_patterns[0].replacement,
            "[MY_SECRET]"
        );
    }

    #[test]
    fn test_config_with_socks_proxy() {
        let yaml = r#"
hosts:
  behind-proxy:
    hostname: "10.0.0.50"
    user: deploy
    auth:
      type: agent
    socks_proxy:
      hostname: proxy.corp.com
      port: 1080
      version: socks5
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(result.is_ok());
        let config = result.unwrap();
        let host = &config.hosts["behind-proxy"];
        assert!(host.socks_proxy.is_some());
        let socks = host.socks_proxy.as_ref().unwrap();
        assert_eq!(socks.hostname, "proxy.corp.com");
        assert_eq!(socks.port, 1080);
    }

    #[test]
    fn test_proxy_jump_and_socks_proxy_mutually_exclusive() {
        let yaml = r#"
hosts:
  conflict:
    hostname: "10.0.0.50"
    user: deploy
    auth:
      type: agent
    proxy_jump: bastion
    socks_proxy:
      hostname: proxy.corp.com
"#;
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_config(file.path());
        assert!(
            matches!(result, Err(BridgeError::ConfigInvalid { field, reason })
            if field.contains("conflict") && reason.contains("mutually exclusive"))
        );
    }

    /// The minimal `http:` block every one of the retired-key tests below
    /// builds on, so the difference between them is exactly one line.
    fn config_with_http(extra: &str) -> String {
        format!(
            r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: deploy
    auth:
      type: agent
http:
  bind: "127.0.0.1:3000"
{extra}"#
        )
    }

    fn load_yaml(yaml: &str) -> Result<Config> {
        let mut file = secure_temp_file();
        file.write_all(yaml.as_bytes()).unwrap();
        load_config(file.path())
    }

    /// THE POSITIVE TWIN, and the reason the two rejections below mean
    /// anything. Both fire on `is_some()`, so a config that never mentions
    /// either key must still load — otherwise "the retired key is refused"
    /// would be satisfied by a loader that refuses every `http:` block, and
    /// the tests would look identical.
    #[test]
    fn an_http_block_without_the_retired_keys_still_loads() {
        let config = load_yaml(&config_with_http("  max_body_size: 2048\n"))
            .expect("an http block that mentions neither retired key must load");
        assert_eq!(config.http.max_body_size, 2048);
        assert!(config.http.session_timeout_seconds.is_none());
        assert!(config.http.max_sessions.is_none());
    }

    #[test]
    fn http_session_timeout_seconds_is_refused_with_its_reason() {
        let result = load_yaml(&config_with_http("  session_timeout_seconds: 1800\n"));
        assert!(
            matches!(&result, Err(BridgeError::ConfigInvalid { field, reason })
            if field == "http.session_timeout_seconds" && reason.contains("stateless")),
            "{result:?}"
        );
    }

    /// Refused even when set to the value that used to be the default:
    /// `1800` and `100` are what an operator who copied the old example file
    /// has, and those are precisely the configs that must be told the bound
    /// is gone. This is why the field is an `Option` and not a defaulted
    /// `u64` — with a `serde` default, this config is byte-identical to one
    /// that says nothing.
    #[test]
    fn http_max_sessions_is_refused_at_its_former_default_too() {
        let result = load_yaml(&config_with_http("  max_sessions: 100\n"));
        assert!(
            matches!(&result, Err(BridgeError::ConfigInvalid { field, reason })
            if field == "http.max_sessions" && reason.contains("sessions.max_sessions")),
            "{result:?}"
        );
    }

    /// `sessions.max_sessions` is a DIFFERENT key that still governs the SSH
    /// connection pool. Conflating the two would turn a documentation fix
    /// into an outage, so the distinction is pinned rather than trusted.
    #[test]
    fn the_ssh_pool_max_sessions_is_untouched() {
        let yaml = r#"
hosts:
  test:
    hostname: "10.0.0.1"
    user: deploy
    auth:
      type: agent
sessions:
  max_sessions: 7
"#;
        let config = load_yaml(yaml).expect("sessions.max_sessions is still a live setting");
        assert_eq!(config.sessions.max_sessions, 7);
    }
}
