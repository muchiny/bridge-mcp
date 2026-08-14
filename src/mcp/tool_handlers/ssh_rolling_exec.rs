//! SSH Rolling Exec Tool Handler
//!
//! Executes a command on a single host as part of a rolling deployment,
//! with an optional health check between hosts. Designed for one-at-a-time
//! execution; use `ssh_exec_multi` for full parallel execution.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::orchestration::OrchestrationCommandBuilder;
use crate::error::Result;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp::standard_tool::{
    StandardTool, StandardToolHandler, impl_common_args, validate_free_form_command,
};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;

#[derive(Debug, Deserialize)]
pub struct SshRollingExecArgs {
    host: String,
    command: String,
    #[serde(default)]
    health_check: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshRollingExecArgs);

#[mcp_standard_tool(
    name = "ssh_rolling_exec",
    group = "orchestration",
    annotation = "mutating"
)]
pub struct RollingExecTool;

impl StandardTool for RollingExecTool {
    type Args = SshRollingExecArgs;

    const NAME: &'static str = "ssh_rolling_exec";

    const DESCRIPTION: &'static str = "Execute a command on ONE host as a single step in a \
        rolling deployment wave: run, validate the health check, then call this tool again on the \
        next host. Always appends a health-check result to output (prints 'no health check \
        configured' when none is supplied) so you can verify each host before advancing. Use \
        ssh_canary_exec for the first/test host before the wave starts. Use ssh_exec_multi when \
        you want full parallel execution across all hosts at once. Use ssh_fleet_diff when you \
        only need to compare read-only command output across hosts without mutating them.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml for the current rolling-wave host"
            },
            "command": {
                "type": "string",
                "description": "The command to execute on this host"
            },
            "health_check": {
                "type": "string",
                "description": "Optional health check command to run after the main command"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 300
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from config)",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a file on the remote host (absolute path)"
            }
        },
        "required": ["host", "command"]
    }"#;

    /// `command` and `health_check` are free-form shell fragments straight from
    /// the request, so they get the same whitelist treatment as `ssh_exec`
    /// instead of the blacklist-only `validate_builtin` the pipeline applies to
    /// builder-produced commands.
    async fn pre_execute(
        args: &SshRollingExecArgs,
        ctx: &ToolContext,
    ) -> Result<Option<ToolCallResult>> {
        validate_free_form_command(ctx, &args.host, &args.command)?;
        if let Some(health_check) = args.health_check.as_deref().filter(|hc| !hc.is_empty()) {
            validate_free_form_command(ctx, &args.host, health_check)?;
        }
        Ok(None)
    }

    fn build_command(args: &SshRollingExecArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(OrchestrationCommandBuilder::build_rolling_command(
            &args.command,
            args.health_check.as_deref(),
        ))
    }
}

pub type SshRollingExecHandler = StandardToolHandler<RollingExecTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRollingExecHandler::new();
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
        let handler = SshRollingExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "command": "echo hi"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshRollingExecHandler::new();
        assert_eq!(handler.name(), "ssh_rolling_exec");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "web1",
            "command": "systemctl restart nginx",
            "health_check": "curl -f http://localhost/health",
            "timeout_seconds": 60
        });
        let args: SshRollingExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "web1");
        assert_eq!(args.command, "systemctl restart nginx");
        assert_eq!(
            args.health_check.as_deref(),
            Some("curl -f http://localhost/health")
        );
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1", "command": "echo hello"});
        let args: SshRollingExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.command, "echo hello");
        assert!(args.health_check.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_build_command() {
        use crate::config::{HostConfig, HostKeyVerification, OsType};
        let host_config = HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
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
        };
        let args = SshRollingExecArgs {
            host: "web1".to_string(),
            command: "systemctl restart nginx".to_string(),
            health_check: Some("curl -f http://localhost/health".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = RollingExecTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("systemctl restart nginx"));
        assert!(cmd.contains("curl -f http://localhost/health"));
        assert!(cmd.contains("echo 'no health check configured'"));
    }

    // ── whitelist enforcement (AUDIT-2026-08 B1) ─────────────

    fn args_with(command: &str, health_check: Option<&str>) -> SshRollingExecArgs {
        SshRollingExecArgs {
            host: "server1".to_string(),
            command: command.to_string(),
            health_check: health_check.map(ToString::to_string),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        }
    }

    #[tokio::test]
    async fn test_command_outside_whitelist_is_denied() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&["^echo"]);
        let result = RollingExecTool::pre_execute(&args_with("id", None), &ctx).await;
        assert!(
            matches!(result, Err(BridgeError::CommandDenied { .. })),
            "command must be whitelist-checked, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_health_check_outside_whitelist_is_denied() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&["^echo"]);
        let result = RollingExecTool::pre_execute(&args_with("echo ok", Some("id")), &ctx).await;
        assert!(
            matches!(result, Err(BridgeError::CommandDenied { .. })),
            "health_check must be whitelist-checked, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_whitelisted_command_is_allowed() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&["^echo"]);
        let result =
            RollingExecTool::pre_execute(&args_with("echo ok", Some("echo healthy")), &ctx).await;
        assert!(result.is_ok(), "got: {result:?}");
    }
}
