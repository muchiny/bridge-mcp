use std::fmt::Write;

use crate::config::{Config, OsType, SecurityMode};

/// Build dynamic instructions for the MCP `initialize` response.
///
/// Includes configured hosts, security mode, enabled/disabled tool groups,
/// key limits, and static usage guidance so that the AI client fully
/// understands the server's configuration.
#[allow(clippy::too_many_lines)]
pub fn build_instructions(config: &Config, tool_count: usize) -> String {
    let mut out = String::with_capacity(2048);

    // --- Header ---
    let _ = writeln!(
        out,
        "Bridge MCP: remote server management via SSH ({tool_count} tools)."
    );

    // --- Configured Hosts ---
    let _ = writeln!(out);
    if config.hosts.is_empty() {
        let _ = writeln!(
            out,
            "HOSTS: None configured. Add hosts to config.yaml, then call ssh_status."
        );
    } else {
        let _ = writeln!(out, "HOSTS:");
        let mut hosts: Vec<_> = config.hosts.iter().collect();
        hosts.sort_by_key(|(alias, _)| *alias);
        for (alias, host) in hosts {
            let os = match host.os_type {
                OsType::Linux => "Linux",
                OsType::Windows => "Windows",
            };
            if let Some(desc) = &host.description {
                let _ = writeln!(out, "- {alias}: {os}, \"{desc}\"");
            } else {
                let _ = writeln!(out, "- {alias}: {os}");
            }
        }
    }

    // --- Security Mode ---
    let _ = writeln!(out);
    let mode_desc = match config.security.mode {
        SecurityMode::Strict => "strict mode (only whitelisted commands allowed)",
        SecurityMode::Standard => {
            "standard mode (ssh_exec checked against whitelist; built-in tools check blacklist only)"
        }
        SecurityMode::Permissive => {
            "permissive mode (minimal command restrictions, blacklist only)"
        }
    };
    let _ = writeln!(out, "SECURITY: {mode_desc}.");

    // --- Disabled Tool Groups ---
    let mut disabled: Vec<&str> = config
        .tool_groups
        .groups
        .iter()
        .filter(|(_, enabled)| !**enabled)
        .map(|(name, _)| name.as_str())
        .collect();
    if !disabled.is_empty() {
        disabled.sort_unstable();
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "DISABLED GROUPS: {} (these tools are unavailable).",
            disabled.join(", ")
        );
    }

    // --- Key Limits ---
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "LIMITS: {}s command timeout, {} char output limit.",
        config.limits.command_timeout_seconds, config.limits.max_output_chars
    );

    // --- Apps ---
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "APPS: Some tools return interactive components (dashboard, table, chart) \
         alongside text. These provide structured views of metrics, containers, \
         services, and processes with action buttons to invoke related tools."
    );

    // --- Roots ---
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "ROOTS: If you declared workspace roots, file operations (ssh_ls, ssh_find, \
         ssh_upload, ssh_download, and the ssh_file_* family) are scoped to those \
         directories for safety."
    );

    // --- Static Guidance ---
    let _ = write!(
        out,
        "\n\
         WORKFLOW: Call ssh_status first to verify host connectivity and OS type.\n\
         \n\
         PREFER SPECIALIZED TOOLS over ssh_exec \u{2014} they validate inputs, \
         structure output, and enforce safety.\n\
         \n\
         ANNOTATIONS: Tools declare readOnlyHint or destructiveHint. \
         Prefer read-only tools for investigation before mutating ones.\n\
         \n\
         OUTPUT: Truncated output returns an output_id. Call \
         ssh_output_fetch output_id=<id> offset=<N> to paginate the rest.\n\
         \n\
         SESSIONS: For multi-step workflows needing shared state (cd, env vars), \
         use ssh_session_create + ssh_session_exec. Close with ssh_session_close when done.\n\
         \n\
         TOKEN SAVINGS: Tools exposing jq_filter (JSON output), yq_filter (YAML), \
         or columns (tabular output) support server-side data reduction. Add \
         output_format=tsv for list-shaped results (60-80% fewer tokens than pretty JSON). \
         ALWAYS use these parameters \u{2014} call describe-tool (CLI) or inspect the tool \
         schema (MCP) to see the exact Reduction Strategy per tool.\n\
         \n\
         OVERRIDES: All tools accept timeout_seconds (override default timeout) and \
         max_output (override default output char limit) as optional parameters.\n\
         \n\
         SAVE OUTPUT: Pass save_output=\"/path/to/file\" to any tool to persist full \
         untruncated output to a file on the remote host \u{2014} useful for large results."
    );

    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::config::{
        AuditConfig, AuthConfig, HostConfig, HostKeyVerification, HttpTransportConfig,
        LimitsConfig, SecurityConfig, SessionConfig, SshConfigDiscovery, ToolGroupsConfig,
    };

    fn default_config() -> Config {
        Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        }
    }

    fn minimal_host(os: OsType, desc: Option<&str>) -> HostConfig {
        HostConfig {
            hostname: "10.0.0.1".to_string(),
            port: 22,
            user: "admin".to_string(),
            auth: AuthConfig::Agent,
            description: desc.map(ToString::to_string),
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: os,
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
        }
    }

    #[test]
    fn test_empty_config() {
        let config = default_config();
        let out = build_instructions(&config, 337);

        assert!(out.contains("337 tools"));
        assert!(out.contains("HOSTS: None configured"));
        assert!(out.contains("standard mode"));
        assert!(!out.contains("DISABLED GROUPS"));
        assert!(out.contains("1800s command timeout"));
        assert!(out.contains("40000 char output limit"));
    }

    #[test]
    fn test_with_hosts_sorted() {
        let mut config = default_config();
        config.hosts.insert(
            "web-prod".to_string(),
            minimal_host(OsType::Linux, Some("Production web")),
        );
        config
            .hosts
            .insert("db-main".to_string(), minimal_host(OsType::Linux, None));
        config.hosts.insert(
            "win-dc".to_string(),
            minimal_host(OsType::Windows, Some("Domain controller")),
        );

        let out = build_instructions(&config, 195);

        // Sorted alphabetically: db-main, web-prod, win-dc
        let db_pos = out.find("db-main").unwrap();
        let web_pos = out.find("web-prod").unwrap();
        let win_pos = out.find("win-dc").unwrap();
        assert!(db_pos < web_pos);
        assert!(web_pos < win_pos);

        assert!(out.contains("- db-main: Linux"));
        assert!(out.contains("- web-prod: Linux, \"Production web\""));
        assert!(out.contains("- win-dc: Windows, \"Domain controller\""));
    }

    #[test]
    fn test_strict_mode() {
        let mut config = default_config();
        config.security.mode = SecurityMode::Strict;
        let out = build_instructions(&config, 337);
        assert!(out.contains("strict mode (only whitelisted commands allowed)"));
    }

    #[test]
    fn test_permissive_mode() {
        let mut config = default_config();
        config.security.mode = SecurityMode::Permissive;
        let out = build_instructions(&config, 337);
        assert!(out.contains("permissive mode"));
    }

    #[test]
    fn test_disabled_groups() {
        let mut config = default_config();
        config
            .tool_groups
            .groups
            .insert("sessions".to_string(), false);
        config
            .tool_groups
            .groups
            .insert("monitoring".to_string(), false);
        config.tool_groups.groups.insert("docker".to_string(), true);

        let out = build_instructions(&config, 190);

        assert!(out.contains("DISABLED GROUPS: monitoring, sessions"));
        assert!(!out.contains("docker"));
    }

    #[test]
    fn test_custom_limits() {
        let mut config = default_config();
        config.limits.command_timeout_seconds = 60;
        config.limits.max_output_chars = 80_000;

        let out = build_instructions(&config, 337);

        assert!(out.contains("60s command timeout"));
        assert!(out.contains("80000 char output limit"));
    }

    #[test]
    fn test_static_guidance_present() {
        let config = default_config();
        let out = build_instructions(&config, 337);

        assert!(out.contains("WORKFLOW: Call ssh_status"));
        assert!(out.contains("PREFER SPECIALIZED TOOLS"));
        assert!(out.contains("ANNOTATIONS:"));
        assert!(out.contains("OUTPUT: Truncated output"));
        assert!(out.contains("ssh_output_fetch"));
        assert!(out.contains("SESSIONS:"));
        assert!(out.contains("APPS:"));
        assert!(out.contains("ROOTS:"));
        assert!(out.contains("TOKEN SAVINGS:"));
        assert!(out.contains("output_format=tsv"));
        assert!(out.contains("yq_filter"));
        assert!(out.contains("OVERRIDES:"));
        assert!(out.contains("timeout_seconds"));
        assert!(out.contains("max_output"));
        assert!(out.contains("SAVE OUTPUT:"));
        assert!(out.contains("save_output="));
    }
}
