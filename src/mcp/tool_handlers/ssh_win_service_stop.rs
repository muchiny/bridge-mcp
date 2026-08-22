//! Handler for the `ssh_win_service_stop` tool.
//!
//! Stops a Windows service on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_service::{
    WindowsServiceCommandBuilder, validate_service_name,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshWinServiceStopArgs {
    host: String,
    name: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinServiceStopArgs);

#[mcp_standard_tool(
    name = "ssh_win_service_stop",
    group = "windows_services",
    annotation = "destructive"
)]
pub struct WinServiceStopTool;

impl StandardTool for WinServiceStopTool {
    type Args = SshWinServiceStopArgs;

    const NAME: &'static str = "ssh_win_service_stop";

    const DESCRIPTION: &'static str = "Stop a Windows service with force flag. Validates the service name and shows status \
        after stopping. Requires appropriate permissions.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "name"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "name": {
                "type": "string",
                "description": "Name of the Windows service (e.g., wuauserv, Spooler, W32Time)"
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
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshWinServiceStopArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsServiceCommandBuilder::build_stop_command(&args.name))
    }

    fn validate(args: &SshWinServiceStopArgs, _host_config: &HostConfig) -> Result<()> {
        validate_service_name(&args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_win_service_stop` tool.
pub type SshWinServiceStopHandler = StandardToolHandler<WinServiceStopTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinServiceStopHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinServiceStopHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "name": "wuauserv"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinServiceStopHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_service_stop");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "name": "wuauserv",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshWinServiceStopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "wuauserv");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "wuauserv"});
        let args: SshWinServiceStopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "wuauserv");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinServiceStopHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "name": "s"});
        let args: SshWinServiceStopArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinServiceStopArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "name": "wuauserv"});
        let result = serde_json::from_value::<SshWinServiceStopArgs>(json);
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
        let args: SshWinServiceStopArgs =
            serde_json::from_value(json!({"host": "s", "name": "wuauserv"})).unwrap();
        let host = test_host_config();
        let cmd = WinServiceStopTool::build_command(&args, &host).unwrap();
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
        let handler = SshWinServiceStopHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(Some(json!({"host": "winhost", "name": "Spooler"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
