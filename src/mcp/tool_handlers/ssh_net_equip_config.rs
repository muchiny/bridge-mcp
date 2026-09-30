//! SSH Network Equipment Config Tool Handler
//!
//! Sends configuration commands to a network device via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::network_equipment::{
    EquipmentType, NETWORK_EQUIPMENT_TAG, NetworkEquipmentCommandBuilder,
};
use crate::error::{BridgeError, Result};
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshNetEquipConfigArgs {
    host: String,
    #[serde(default)]
    equipment_type: Option<String>,
    commands: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshNetEquipConfigArgs);

#[mcp_standard_tool(
    name = "ssh_net_equip_config",
    group = "network_equipment",
    annotation = "destructive"
)]
pub struct NetEquipConfigTool;

impl StandardTool for NetEquipConfigTool {
    type Args = SshNetEquipConfigArgs;

    const NAME: &'static str = "ssh_net_equip_config";

    const DESCRIPTION: &'static str = "Send configuration commands to a network device \
        (router/switch/firewall). Automatically wraps commands in the appropriate configure \
        mode: Cisco → `configure terminal ... end`; Juniper → `configure ... commit\\nexit`; \
        Fortinet → `config system global ... end`; MikroTik/generic → commands sent as-is \
        (no wrapper). DESTRUCTIVE — requires elicitation confirmation. Read the running \
        config first with ssh_net_equip_show_run. Persist changes with ssh_net_equip_save \
        (Cisco: write memory; Juniper: rescue save; MikroTik: backup file). \
        Only runs on a host whose config.yaml 'tags' list contains \
        'network-equipment': the commands text is sent as-is, so the operator must \
        declare the far end is a device CLI and not a shell. 'sudo' is refused.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "equipment_type": {
                "type": "string",
                "description": "Device vendor/OS. Accepted values: cisco (alias: ios), juniper (alias: junos), mikrotik (alias: routeros), fortinet (aliases: fortios, fortigate), or any other string for generic. Default: generic.",
                "enum": ["cisco", "juniper", "mikrotik", "fortinet", "generic"]
            },
            "commands": {
                "type": "string",
                "description": "Configuration commands to apply, newline-separated for multiple commands (e.g. \"interface Gi0/1\\nno shutdown\" for Cisco). These are the inner commands — do not include configure terminal / end yourself, the tool adds the correct wrapper per vendor."
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "commands"]
    }"#;

    /// `sudo` is refused on this tool, not ignored.
    ///
    /// The far end is a device CLI, so there is no POSIX `sudo` to run there in
    /// the first place; the reason it has to be *refused* is what `sudo` would
    /// do on a host that is not the device the operator believes it is. The
    /// pipeline elevates at step 5b by wrapping the built command in
    /// `sudo -n bash -c '…'`, and for `EquipmentType::Generic` the built
    /// command is the request's `commands` text verbatim — so `sudo: true` here
    /// used to run that text as root, ahead of the blacklist, with the
    /// whitelist already skipped by `validate_builtin`.
    const ALLOWS_ELEVATION: bool = false;

    fn build_command(args: &SshNetEquipConfigArgs, _host_config: &HostConfig) -> Result<String> {
        let eq_type = args
            .equipment_type
            .as_deref()
            .map_or(EquipmentType::Generic, EquipmentType::from_str_loose);
        Ok(NetworkEquipmentCommandBuilder::build_config_command(
            eq_type,
            &args.commands,
        ))
    }

    /// Refuse any host the operator has not marked as network equipment.
    ///
    /// `commands` is interpolated verbatim into the remote command (see
    /// [`NETWORK_EQUIPMENT_TAG`] for why it cannot be escaped or whitelisted),
    /// so what keeps this tool from being `ssh_exec`-without-a-whitelist is the
    /// *host*: the operator states in `config.yaml` that the far end speaks a
    /// device CLI rather than a shell, and only then does the tool run.
    ///
    /// This lives in `validate` and not in [`Self::build_command`]: `validate`
    /// is the pipeline step that is handed the [`HostConfig`], and
    /// `build_command` is called directly by this module's own
    /// `test_build_command_defaults`, so a guard there would be bypassed by
    /// exactly the test that has to stay meaningful.
    fn validate(args: &SshNetEquipConfigArgs, host_config: &HostConfig) -> Result<()> {
        // Exact and case-sensitive, deliberately not `HostConfig::has_tag` —
        // see `NETWORK_EQUIPMENT_TAG`.
        if host_config.tags.iter().any(|t| t == NETWORK_EQUIPMENT_TAG) {
            return Ok(());
        }
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Host '{}' is not marked as network equipment: add the tag \
                 '{NETWORK_EQUIPMENT_TAG}' to its 'tags' list in config.yaml to allow \
                 '{}' on it. The tool sends the 'commands' text to the host as-is, with \
                 the command whitelist skipped, so it runs only where an operator has \
                 declared that the far end is a device CLI and not a shell.",
                args.host,
                Self::NAME,
            ),
        })
    }
}

/// Handler for the `ssh_net_equip_config` tool.
pub type SshNetEquipConfigHandler = StandardToolHandler<NetEquipConfigTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshNetEquipConfigHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshNetEquipConfigHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "commands": "interface Gi0/1"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshNetEquipConfigHandler::new();
        assert_eq!(handler.name(), "ssh_net_equip_config");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("commands")));
    }

    fn test_host_config() -> crate::config::HostConfig {
        crate::config::HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: crate::config::HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: crate::config::OsType::default(),
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

    /// `build_command` is deliberately unchanged by the host-tag guard, and is
    /// called here directly — which is exactly why the guard lives in
    /// `validate` instead. `test_host_config` carries no tags, so this call
    /// would be refused through the pipeline; the builder itself still returns
    /// the same string it always did.
    ///
    /// The assertion is the reason the guard had to exist: with no
    /// `equipment_type`, `EquipmentType::Generic` applies, its wrapper is empty,
    /// and the command IS the caller's `commands` text verbatim. Pinning that
    /// keeps a future "generic gets a wrapper too" change from quietly removing
    /// the premise the guard is argued from.
    #[test]
    fn test_build_command_defaults() {
        let args: SshNetEquipConfigArgs = serde_json::from_value(
            json!({"host": "s", "commands": "interface Gi0/1\nno shutdown"}),
        )
        .unwrap();
        let host = test_host_config();
        let cmd = NetEquipConfigTool::build_command(&args, &host).unwrap();
        assert_eq!(cmd, "interface Gi0/1\nno shutdown");
    }

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    /// One host named `server1`, carrying exactly `tags`.
    ///
    /// `tags` is a parameter and not `Vec::new()` because the tag is now the
    /// difference between the tool running and the tool refusing — the two
    /// directions have to be reachable from the same fixture, or "marked passes"
    /// and "unmarked refuses" would be testing two different hosts.
    fn server1_hosts(
        tags: Vec<String>,
    ) -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "test".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags,
                os_type: OsType::default(),
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
            },
        );
        hosts
    }

    /// The most permissive context this tool can be called in: mode
    /// `Permissive`, empty blacklist. It is the point of the refusal tests
    /// below that the guard holds even here — the security policy is not what
    /// stops this tool, because `validate_builtin` skips the whitelist for
    /// specialised tools by design.
    fn permissive_ctx(
        mock_out: crate::ssh::CommandOutput,
        tags: Vec<String>,
    ) -> crate::ports::ToolContext {
        use crate::config::SessionConfig;
        use crate::config::{Config, LimitsConfig, SecurityConfig, SecurityMode};
        use crate::domain::CommandHistory;
        use crate::domain::ExecuteCommandUseCase;
        use crate::domain::TunnelManager;
        use crate::domain::history::HistoryConfig;
        use crate::ports::ExecutorRouter;
        use crate::security::AuditLogger;
        use crate::security::RateLimiter;
        use crate::security::{CommandValidator, Sanitizer};
        use crate::ssh::SessionManager;
        use std::sync::Arc;
        let sec = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: Vec::new(),
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts: server1_hosts(tags),
            security: sec.clone(),
            limits: LimitsConfig::default(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&sec));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));
        crate::ports::ToolContext {
            mrtr: crate::ports::MrtrSlot::default(),
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::mock(mock_out)),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    fn marked() -> Vec<String> {
        vec![NETWORK_EQUIPMENT_TAG.to_string()]
    }

    /// The unmarked host is the pre-fix default, and it was the whole defect:
    /// `commands` reached a POSIX shell verbatim, with the whitelist skipped by
    /// `validate_builtin` and the context here as permissive as it gets. This
    /// test was `test_full_pipeline_success` — the tool succeeded on a host
    /// nobody had declared to be a network device.
    #[tokio::test]
    async fn unmarked_host_is_refused() {
        let handler = SshNetEquipConfigHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"), Vec::new());
        let err = handler
            .execute(
                // A POSIX command, not a device one: on a host that is really a
                // Linux box this is what used to run.
                Some(json!({"host": "server1", "commands": "cat /etc/shadow"})),
                &ctx,
            )
            .await
            .expect_err("an unmarked host must be refused");
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(
                    reason.contains("server1") && reason.contains(NETWORK_EQUIPMENT_TAG),
                    "the refusal must name the host and the tag to add: {reason}"
                );
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    /// The other direction, and the one that makes the test above mean
    /// something: without it a guard that refused every host would pass too.
    #[tokio::test]
    async fn marked_host_runs_the_command() {
        let handler = SshNetEquipConfigHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"), marked());
        let result = handler
            .execute(
                Some(json!({"host": "server1", "commands": "interface Gi0/1\nno shutdown"})),
                &ctx,
            )
            .await
            .expect("a host tagged as network equipment must be allowed");
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }

    /// A near-miss spelling is a non-match, not a grant: the comparison is
    /// exact and case-sensitive, unlike `HostConfig::has_tag`, so a tag that
    /// only looks right does not open the path.
    #[tokio::test]
    async fn a_tag_that_is_not_the_reserved_one_is_refused() {
        for tag in ["Network-Equipment", "network_equipment", "network-equip"] {
            let handler = SshNetEquipConfigHandler::new();
            let ctx = permissive_ctx(mock_output("mock output"), vec![tag.to_string()]);
            let err = handler
                .execute(
                    Some(json!({"host": "server1", "commands": "show version"})),
                    &ctx,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(err, BridgeError::CommandDenied { .. }),
                "{tag:?} must not grant the tool: {err:?}"
            );
        }
    }

    /// The escalation half of the defect. `PrivilegeArgs::extract` runs for
    /// every pipeline tool, and step 5b elevates BEFORE the blacklist, so
    /// `sudo: true` wrapped this tool's verbatim `commands` text in
    /// `sudo -n bash -c '…'` and ran it as root. Marked host on purpose: the
    /// tag guard must not be what refuses here.
    #[tokio::test]
    async fn sudo_is_refused_even_on_a_marked_host() {
        let handler = SshNetEquipConfigHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"), marked());
        let err = handler
            .execute(
                Some(json!({"host": "server1", "commands": "show version", "sudo": true})),
                &ctx,
            )
            .await
            .expect_err("sudo must be refused, not silently dropped");
        match err {
            BridgeError::CommandDenied { reason } => assert!(
                reason.contains("sudo") && reason.contains(NetEquipConfigTool::NAME),
                "the refusal must name the param and the tool: {reason}"
            ),
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    /// The refusal above is the pipeline half; this is the schema half. The
    /// param must also stop being advertised, or `describe-tool` would offer a
    /// `sudo` that always fails — and on the CLI the schema is load-bearing:
    /// `bridge-mcp tool` rejects keys the enriched schema does not declare, so
    /// leaving `sudo` out is what makes it fail at parse time there instead of
    /// mid-pipeline.
    #[test]
    fn the_tool_does_not_advertise_elevation() {
        // A `const` block on purpose: flipping the const back should not
        // compile this test, not merely fail it.
        const { assert!(!NetEquipConfigTool::ALLOWS_ELEVATION) };
        assert!(!SshNetEquipConfigHandler::new().supports_elevation());
    }
}
