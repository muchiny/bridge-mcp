//! Handler for the `ssh_win_net_ping` tool.
//!
//! Pings a target host from a remote Windows machine via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_network::WindowsNetworkCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshWinNetPingArgs {
    host: String,
    target: String,
    #[serde(default)]
    count: Option<u32>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinNetPingArgs);

#[mcp_standard_tool(
    name = "ssh_win_net_ping",
    group = "windows_network",
    annotation = "read_only"
)]
pub struct WinNetPingTool;

impl StandardTool for WinNetPingTool {
    type Args = SshWinNetPingArgs;

    const NAME: &'static str = "ssh_win_net_ping";

    const DESCRIPTION: &'static str = "Ping a target host from a Windows machine using PowerShell Test-Connection; \
        returns round-trip time statistics. Windows-only — for Linux hosts use ssh_net_ping instead. \
        The target param is the destination to ping; host is the Windows machine that sends the probe.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "target"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "target": {
                "type": "string",
                "description": "Hostname or IP address to ping; must contain only alphanumeric, hyphen, dot, colon, or bracket characters (no spaces or shell metacharacters)"
            },
            "count": {
                "type": "integer",
                "description": "Number of ping packets to send (default: 4)",
                "maximum": 100
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshWinNetPingArgs, _host_config: &HostConfig) -> Result<String> {
        let count = args.count.unwrap_or(4);
        WindowsNetworkCommandBuilder::ping(&args.target, count)
    }
}

/// Handler for the `ssh_win_net_ping` tool.
pub type SshWinNetPingHandler = StandardToolHandler<WinNetPingTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinNetPingHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinNetPingHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "target": "8.8.8.8"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinNetPingHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_net_ping");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("target")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "target": "8.8.8.8",
            "count": 10,
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshWinNetPingArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "8.8.8.8");
        assert_eq!(args.count, Some(10));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "target": "8.8.8.8"});
        let args: SshWinNetPingArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "8.8.8.8");
        assert!(args.count.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinNetPingHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("count"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "target": "t"});
        let args: SshWinNetPingArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinNetPingArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "target": "8.8.8.8"});
        let result = serde_json::from_value::<SshWinNetPingArgs>(json);
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
        let args: SshWinNetPingArgs =
            serde_json::from_value(json!({"host": "s", "target": "8.8.8.8"})).unwrap();
        let host = test_host_config();
        let cmd = WinNetPingTool::build_command(&args, &host).unwrap();
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
        let handler = SshWinNetPingHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(Some(json!({"host": "winhost", "target": "8.8.8.8"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
