//! SSH config parser for auto-discovery of hosts from `~/.ssh/config`.
//!
//! Parses standard SSH config directives (`Host`, `HostName`, `Port`, `User`,
//! `IdentityFile`, `ProxyJump`) and converts them into `HostConfig` entries.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use tracing::{debug, warn};

use super::types::{AuthConfig, HostConfig, HostKeyVerification, OsType};

/// Parse an SSH config file and return discovered hosts as `HostConfig` entries.
///
/// Hosts with wildcard patterns (containing `*` or `?`) are skipped.
/// The special `Host *` block is used as a fallback for default values.
///
/// # Arguments
///
/// * `path` - Path to the SSH config file (e.g., `~/.ssh/config`)
/// * `exclude` - Host alias patterns to exclude from discovery
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn parse_ssh_config(
    path: &Path,
    exclude: &[String],
) -> std::io::Result<HashMap<String, HostConfig>> {
    let content = fs::read_to_string(path)?;
    Ok(parse_ssh_config_content(&content, exclude))
}

/// Parse SSH config content string into host configurations.
#[must_use]
pub fn parse_ssh_config_content(content: &str, exclude: &[String]) -> HashMap<String, HostConfig> {
    let mut hosts = HashMap::new();
    let mut current_alias: Option<String> = None;
    let mut current_host = PartialHost::default();
    let mut global_defaults = PartialHost::default();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse key-value (supports both "Key Value" and "Key=Value")
        let Some((key, value)) = parse_directive(line) else {
            continue;
        };

        if key.eq_ignore_ascii_case("Host") {
            // Finalize previous host block
            finalize(
                &mut hosts,
                current_alias.take(),
                &current_host,
                &global_defaults,
            );

            // Start new host block
            let alias = value.to_string();

            // Skip wildcard patterns
            if alias.contains('*') || alias.contains('?') {
                if alias == "*" {
                    // Use "*" as marker to collect global defaults
                    current_alias = Some("*".to_string());
                    current_host = PartialHost::default();
                }
                continue;
            }

            // Check exclude list
            if exclude.iter().any(|e| e == &alias) {
                debug!(host = %alias, "Excluded from SSH config discovery");
                current_alias = None;
                current_host = PartialHost::default();
                continue;
            }

            current_alias = Some(alias);
            current_host = PartialHost::default();
        } else if current_alias.as_deref() == Some("*") {
            // Parsing global defaults from "Host *"
            apply_directive(&mut global_defaults, &key, value);
        } else if current_alias.is_some() {
            apply_directive(&mut current_host, &key, value);
        }
    }

    // Finalize last host block
    finalize(&mut hosts, current_alias, &current_host, &global_defaults);

    hosts
}

/// Close one `Host` block, unless it is the `*` marker.
///
/// There are two places a block ends — the next `Host` line, and the end of the
/// file — and they used to be two copies of this logic. Only the second
/// excluded `"*"`, so a config whose `Host *` block set `HostName` and was
/// followed by ANY further `Host` line yielded a discovered host literally named
/// `*`: `merge_ssh_config_hosts` then put it in `config.hosts`, where it is
/// selectable by name and connects wherever the global default pointed.
/// `HostName %h` under `Host *` is a real idiom, so this was reachable from an
/// ordinary `~/.ssh/config`.
///
/// `*` is a MARKER, never a host. It exists only so the loop knows the
/// directives it is reading belong in `global_defaults`. Found by
/// `fuzz_ssh_config_parser` once the target had seeds; the assertion that
/// caught it had been sitting there unreached.
///
/// One function rather than two call sites doing the same thing, so the guard
/// cannot go missing from one of them again.
fn finalize(
    hosts: &mut HashMap<String, HostConfig>,
    alias: Option<String>,
    current: &PartialHost,
    defaults: &PartialHost,
) {
    if let Some(alias) = alias
        && alias != "*"
        && let Some(host_config) = current.to_host_config(defaults)
    {
        hosts.insert(alias, host_config);
    }
}

/// Intermediate representation during parsing
#[derive(Default, Clone)]
struct PartialHost {
    hostname: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
}

impl PartialHost {
    /// Convert to a full `HostConfig`, using global defaults as fallback.
    /// Returns `None` if essential fields (hostname, user) cannot be determined.
    fn to_host_config(&self, defaults: &PartialHost) -> Option<HostConfig> {
        let hostname = self
            .hostname
            .as_ref()
            .or(defaults.hostname.as_ref())
            .cloned()?;

        let user = self
            .user
            .as_ref()
            .or(defaults.user.as_ref())
            .cloned()
            .unwrap_or_else(|| {
                // Fallback to current system user
                std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "root".to_string())
            });

        let port = self.port.or(defaults.port).unwrap_or(22);

        let identity_file = self
            .identity_file
            .as_ref()
            .or(defaults.identity_file.as_ref());

        let auth = if let Some(key_path) = identity_file {
            // Expand ~ in the path
            let expanded = crate::path_utils::home_expand_or_input(key_path);
            let path = std::path::Path::new(&expanded);
            if path.exists() {
                AuthConfig::Key {
                    path: key_path.clone(),
                    passphrase: None,
                }
            } else {
                debug!(
                    path = %key_path,
                    "SSH key not found, falling back to agent auth"
                );
                AuthConfig::Agent
            }
        } else {
            AuthConfig::Agent
        };

        let proxy_jump = self
            .proxy_jump
            .as_ref()
            .or(defaults.proxy_jump.as_ref())
            .cloned();

        Some(HostConfig {
            hostname,
            port,
            user,
            auth,
            description: Some("Discovered from ~/.ssh/config".to_string()),
            host_key_verification: HostKeyVerification::AcceptNew,
            proxy_jump,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::Linux,
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),
            #[cfg(feature = "winrm")]
            winrm_use_tls: None,
            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,
            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,
            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        })
    }
}

/// Parse a single SSH config directive line into (key, value).
fn parse_directive(line: &str) -> Option<(String, &str)> {
    // Handle "Key=Value" format
    if let Some((key, value)) = line.split_once('=') {
        let key = key.trim().to_string();
        let value = value.trim();
        if !key.is_empty() && !value.is_empty() {
            return Some((key, value));
        }
    }

    // Handle "Key Value" format (split on first whitespace)
    let mut parts = line.splitn(2, char::is_whitespace);
    let key = parts.next()?.trim().to_string();
    let value = parts.next()?.trim();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Apply a parsed directive to a `PartialHost`.
fn apply_directive(host: &mut PartialHost, key: &str, value: &str) {
    match key.to_ascii_lowercase().as_str() {
        "hostname" => host.hostname = Some(value.to_string()),
        "port" => {
            // `0` parses as a `u16` and is not a destination port: TCP reserves
            // it, and a host carrying it can never connect. Without this the
            // file treated the two kinds of invalid differently — `Port
            // notanumber` warned and fell back to 22, `Port 0` was accepted in
            // silence and failed later with an error accusing the network.
            // Found by `fuzz_ssh_config_parser` once the target had seeds; the
            // `port > 0` assertion had been sitting there unreached.
            match value.parse::<u16>() {
                Ok(port) if port != 0 => host.port = Some(port),
                _ => warn!(value = %value, "Invalid port number in SSH config"),
            }
        }
        "user" => host.user = Some(value.to_string()),
        "identityfile" => host.identity_file = Some(value.to_string()),
        "proxyjump" => host.proxy_jump = Some(value.to_string()),
        _ => {
            // Ignore unsupported directives (ForwardAgent, etc.)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_config() {
        let hosts = parse_ssh_config_content("", &[]);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_parse_comments_only() {
        let content = "# This is a comment\n# Another comment\n";
        let hosts = parse_ssh_config_content(content, &[]);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_parse_single_host() {
        let content = "\
Host myserver
    HostName 192.168.1.100
    User admin
    Port 2222
";
        let hosts = parse_ssh_config_content(content, &[]);
        assert_eq!(hosts.len(), 1);

        let host = &hosts["myserver"];
        assert_eq!(host.hostname, "192.168.1.100");
        assert_eq!(host.user, "admin");
        assert_eq!(host.port, 2222);
        assert_eq!(host.host_key_verification, HostKeyVerification::AcceptNew);
    }

    #[test]
    fn test_parse_multiple_hosts() {
        let content = "\
Host server1
    HostName 10.0.0.1
    User deploy

Host server2
    HostName 10.0.0.2
    User root
    Port 2222
";
        let hosts = parse_ssh_config_content(content, &[]);
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains_key("server1"));
        assert!(hosts.contains_key("server2"));
        assert_eq!(hosts["server1"].hostname, "10.0.0.1");
        assert_eq!(hosts["server2"].port, 2222);
    }

    #[test]
    fn test_parse_wildcard_hosts_skipped() {
        let content = "\
Host *
    User default_user

Host prod-*
    User deploy

Host myserver
    HostName 10.0.0.1
";
        let hosts = parse_ssh_config_content(content, &[]);
        assert_eq!(hosts.len(), 1);
        assert!(hosts.contains_key("myserver"));
    }

    #[test]
    fn test_parse_global_defaults_applied() {
        let content = "\
Host *
    User global_user
    Port 2222

Host myserver
    HostName 10.0.0.1
";
        let hosts = parse_ssh_config_content(content, &[]);
        assert_eq!(hosts.len(), 1);

        let host = &hosts["myserver"];
        assert_eq!(host.user, "global_user");
        assert_eq!(host.port, 2222);
    }

    #[test]
    fn test_parse_host_overrides_defaults() {
        let content = "\
Host *
    User global_user
    Port 2222

Host myserver
    HostName 10.0.0.1
    User specific_user
    Port 22
";
        let hosts = parse_ssh_config_content(content, &[]);
        let host = &hosts["myserver"];
        assert_eq!(host.user, "specific_user");
        assert_eq!(host.port, 22);
    }

    #[test]
    fn test_parse_identity_file() {
        let content = "\
Host myserver
    HostName 10.0.0.1
    User admin
    IdentityFile ~/.ssh/nonexistent_key_for_test
";
        let hosts = parse_ssh_config_content(content, &[]);
        let host = &hosts["myserver"];
        // Key doesn't exist, so it falls back to agent auth
        assert!(matches!(host.auth, AuthConfig::Agent));
    }

    #[test]
    fn test_parse_proxy_jump() {
        let content = "\
Host bastion
    HostName bastion.example.com
    User admin

Host internal
    HostName 10.0.0.5
    User deploy
    ProxyJump bastion
";
        let hosts = parse_ssh_config_content(content, &[]);
        assert_eq!(hosts["internal"].proxy_jump, Some("bastion".to_string()));
        assert!(hosts["bastion"].proxy_jump.is_none());
    }

    #[test]
    fn test_parse_exclude_hosts() {
        let content = "\
Host server1
    HostName 10.0.0.1
    User admin

Host secret-server
    HostName 10.0.0.99
    User admin

Host server2
    HostName 10.0.0.2
    User admin
";
        let exclude = vec!["secret-server".to_string()];
        let hosts = parse_ssh_config_content(content, &exclude);
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains_key("server1"));
        assert!(hosts.contains_key("server2"));
        assert!(!hosts.contains_key("secret-server"));
    }

    #[test]
    fn test_parse_equals_format() {
        let content = "\
Host myserver
    HostName=10.0.0.1
    User=admin
    Port=3333
";
        let hosts = parse_ssh_config_content(content, &[]);
        let host = &hosts["myserver"];
        assert_eq!(host.hostname, "10.0.0.1");
        assert_eq!(host.user, "admin");
        assert_eq!(host.port, 3333);
    }

    #[test]
    fn test_parse_host_without_hostname_skipped() {
        let content = "\
Host incomplete
    User admin

Host complete
    HostName 10.0.0.1
    User admin
";
        let hosts = parse_ssh_config_content(content, &[]);
        assert_eq!(hosts.len(), 1);
        assert!(hosts.contains_key("complete"));
        assert!(!hosts.contains_key("incomplete"));
    }

    #[test]
    fn test_parse_invalid_port_ignored() {
        let content = "\
Host myserver
    HostName 10.0.0.1
    User admin
    Port notanumber
";
        let hosts = parse_ssh_config_content(content, &[]);
        let host = &hosts["myserver"];
        assert_eq!(host.port, 22); // Falls back to default
    }

    #[test]
    fn test_parse_description_is_set() {
        let content = "\
Host myserver
    HostName 10.0.0.1
    User admin
";
        let hosts = parse_ssh_config_content(content, &[]);
        assert_eq!(
            hosts["myserver"].description,
            Some("Discovered from ~/.ssh/config".to_string())
        );
    }

    #[test]
    fn test_parse_case_insensitive_directives() {
        let content = "\
Host myserver
    HOSTNAME 10.0.0.1
    USER admin
    PORT 3333
";
        let hosts = parse_ssh_config_content(content, &[]);
        let host = &hosts["myserver"];
        assert_eq!(host.hostname, "10.0.0.1");
        assert_eq!(host.user, "admin");
        assert_eq!(host.port, 3333);
    }

    #[test]
    fn test_parse_directive_equals_format() {
        let result = parse_directive("HostName=10.0.0.1");
        assert!(result.is_some());
        let (key, value) = result.unwrap();
        assert_eq!(key, "HostName");
        assert_eq!(value, "10.0.0.1");
    }

    #[test]
    fn test_parse_directive_empty_value() {
        let result = parse_directive("HostName ");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_directive_empty_line() {
        let result = parse_directive("");
        assert!(result.is_none());
    }

    #[test]
    fn test_apply_directive_identity_file() {
        let mut host = PartialHost::default();
        apply_directive(&mut host, "IdentityFile", "~/.ssh/id_ed25519");
        assert_eq!(host.identity_file, Some("~/.ssh/id_ed25519".to_string()));
    }

    #[test]
    fn test_apply_directive_proxy_jump() {
        let mut host = PartialHost::default();
        apply_directive(&mut host, "ProxyJump", "bastion");
        assert_eq!(host.proxy_jump, Some("bastion".to_string()));
    }

    #[test]
    fn test_apply_directive_invalid_port_ignored() {
        let mut host = PartialHost::default();
        apply_directive(&mut host, "Port", "not_a_number");
        assert!(host.port.is_none());
    }

    #[test]
    fn test_apply_directive_unknown_key_ignored() {
        let mut host = PartialHost::default();
        apply_directive(&mut host, "ForwardAgent", "yes");
        // Should not panic or affect known fields
        assert!(host.hostname.is_none());
    }

    #[test]
    fn test_partial_host_no_hostname_returns_none() {
        let host = PartialHost {
            user: Some("admin".to_string()),
            ..PartialHost::default()
        };
        let defaults = PartialHost::default();
        assert!(host.to_host_config(&defaults).is_none());
    }

    /// `Host *` is a marker, and a marker is not a host.
    ///
    /// A block ends in two places — at the next `Host` line and at the end of
    /// the file — and only the second used to exclude `"*"`. So this config
    /// produced a discovered host literally named `*`, pointing at whatever the
    /// global default said, which `merge_ssh_config_hosts` then made selectable
    /// by name. `HostName %h` under `Host *` is a real idiom, so an ordinary
    /// `~/.ssh/config` reached it.
    ///
    /// The trailing `Host prod` is what makes this test what it is: without a
    /// second `Host` line the buggy branch never runs, and the test passes
    /// against the defect.
    #[test]
    fn a_wildcard_block_followed_by_another_host_is_not_itself_a_host() {
        let content = "Host *\n  HostName fallback.internal\n  User deploy\n\nHost prod\n  HostName 10.0.0.1\n";
        let hosts = parse_ssh_config_content(content, &[]);

        assert!(
            !hosts.contains_key("*"),
            "the global-defaults marker became a host: {:?}",
            hosts.keys().collect::<Vec<_>>()
        );

        // And the defaults it carried still reach the real host, so the fix
        // removes the entry without removing the mechanism.
        let prod = hosts.get("prod").expect("prod is a real host");
        assert_eq!(prod.hostname, "10.0.0.1");
        assert_eq!(prod.user, "deploy", "User came from the `Host *` block");
    }

    /// The same block at the END of the file, which was already correct — kept
    /// so the two paths are pinned together and cannot drift apart again.
    #[test]
    fn a_trailing_wildcard_block_is_not_a_host_either() {
        let hosts = parse_ssh_config_content("Host *\n  HostName fallback.internal\n", &[]);
        assert!(
            hosts.is_empty(),
            "got {:?}",
            hosts.keys().collect::<Vec<_>>()
        );
    }

    /// `Port 0` is not a port, and must be treated as the invalid value it is.
    ///
    /// It parses as a `u16`, which is the whole trap: the file's other invalid
    /// port (`Port notanumber`) warns and falls back to 22, while this one used
    /// to be accepted in silence and produce a host that can never connect —
    /// failing later with an error that accuses the network.
    #[test]
    fn a_zero_port_falls_back_like_any_other_invalid_port() {
        let content = "Host myserver\n  HostName 10.0.0.1\n  User admin\n  Port 0\n";
        let hosts = parse_ssh_config_content(content, &[]);
        assert_eq!(hosts["myserver"].port, 22, "0 must fall back, not stick");
    }
}
