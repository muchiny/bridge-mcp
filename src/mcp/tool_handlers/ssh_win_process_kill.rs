//! Handler for the `ssh_win_process_kill` tool.
//!
//! Kills a process on a Windows host via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_process::WindowsProcessCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshWinProcessKillArgs {
    host: String,
    pid: u32,
    #[serde(default)]
    force: bool,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinProcessKillArgs);

#[mcp_standard_tool(
    name = "ssh_win_process_kill",
    group = "windows_process",
    annotation = "destructive"
)]
pub struct WinProcessKillTool;

impl StandardTool for WinProcessKillTool {
    type Args = SshWinProcessKillArgs;

    const NAME: &'static str = "ssh_win_process_kill";

    const DESCRIPTION: &'static str = "Kill a process on a Windows host by PID via PowerShell Stop-Process. Default is a \
        graceful stop; set force=true to forcefully terminate a process that does not respond. \
        Use ssh_win_process_list or ssh_win_process_by_name first to find the target PID. \
        For Linux hosts use ssh_process_kill instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "pid"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "pid": {
                "type": "integer",
                "description": "Process ID to kill",
                "minimum": 0
            },
            "force": {
                "type": "boolean",
                "description": "Force kill the process (default: false)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the bridge server"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshWinProcessKillArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsProcessCommandBuilder::kill(args.pid, args.force))
    }

    /// Confirm destructive operation via `elicitation/create` before
    /// running the underlying command. Falls back to a no-op when the
    /// client does not advertise the elicitation capability — the
    /// global `security.require_elicitation_on_destructive` gate still
    /// applies in that case.
    async fn pre_execute(args: &Self::Args, ctx: &ToolContext) -> Result<Option<ToolCallResult>> {
        let summary = format!(
            "Kill Windows PID `{}` (force=`{}`) on host `{}`",
            args.pid, args.force, args.host,
        );
        match ctx.elicit_confirm(Self::NAME, &summary).await? {
            Some(false) => Ok(Some(ToolCallResult::error(
                "User declined destructive operation".to_string(),
            ))),
            _ => Ok(None),
        }
    }
}

/// Handler for the `ssh_win_process_kill` tool.
pub type SshWinProcessKillHandler = StandardToolHandler<WinProcessKillTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinProcessKillHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinProcessKillHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "pid": 1234});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinProcessKillHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_process_kill");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("pid")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "pid": 1234,
            "force": true,
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshWinProcessKillArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.pid, 1234);
        assert!(args.force);
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "pid": 5678});
        let args: SshWinProcessKillArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.pid, 5678);
        assert!(!args.force);
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinProcessKillHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("force"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "pid": 1});
        let args: SshWinProcessKillArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinProcessKillArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "pid": "not_a_number"});
        let result = serde_json::from_value::<SshWinProcessKillArgs>(json);
        assert!(result.is_err());
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
            os_type: crate::config::OsType::Windows,
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
    fn test_build_command_defaults() {
        let args: SshWinProcessKillArgs =
            serde_json::from_value(json!({"host": "s", "pid": 1234})).unwrap();
        let host = test_host_config();
        let cmd = WinProcessKillTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn win_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "winhost".to_string(),
            HostConfig {
                hostname: "10.0.0.1".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Windows,
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
    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshWinProcessKillHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(Some(json!({"host": "winhost", "pid": 1234})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
