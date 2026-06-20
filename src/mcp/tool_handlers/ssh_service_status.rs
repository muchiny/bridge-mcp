//! Handler for the `ssh_service_status` tool.
//!
//! Shows the status of a systemd service on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::systemd::{SystemdCommandBuilder, validate_service_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshServiceStatusArgs {
    host: String,
    service: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshServiceStatusArgs);

#[mcp_standard_tool(
    name = "ssh_service_status",
    group = "systemd",
    annotation = "read_only"
)]
pub struct ServiceStatusTool;

impl StandardTool for ServiceStatusTool {
    type Args = SshServiceStatusArgs;

    const NAME: &'static str = "ssh_service_status";

    const DESCRIPTION: &'static str = "Show the status of a systemd service on a remote host (systemctl status). Prefer \
        this over ssh_exec as it provides structured output with active state, loaded state, \
        PID, memory usage, and recent log entries. Use ssh_service_list first to discover \
        available service names. Use ssh_service_logs for detailed log history. \
        For Windows hosts use ssh_win_service_status instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "service"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "service": {
                "type": "string",
                "description": "Name of the systemd service (e.g., nginx, sshd, docker)"
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

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshServiceStatusArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SystemdCommandBuilder::build_status_command(&args.service))
    }

    fn validate(args: &SshServiceStatusArgs, _host_config: &HostConfig) -> Result<()> {
        validate_service_name(&args.service)?;
        Ok(())
    }
}

/// Handler for the `ssh_service_status` tool.
pub type SshServiceStatusHandler = StandardToolHandler<ServiceStatusTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshServiceStatusHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshServiceStatusHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "service": "nginx"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshServiceStatusHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_service_status");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("service")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "service": "nginx",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshServiceStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "service": "nginx"});
        let args: SshServiceStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshServiceStatusHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "service": "s"});
        let args: SshServiceStatusArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshServiceStatusArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "service": "nginx"});
        let result = serde_json::from_value::<SshServiceStatusArgs>(json);
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

    #[test]
    fn test_build_command_defaults() {
        let args: SshServiceStatusArgs =
            serde_json::from_value(json!({"host": "s", "service": "nginx"})).unwrap();
        let host = test_host_config();
        let cmd = ServiceStatusTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("nginx"));
    }

    #[tokio::test]
    async fn test_os_guard_rejects_windows_host() {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType as Os};
        use std::collections::HashMap;
        let mut hosts = HashMap::new();
        hosts.insert(
            "winbox".to_string(),
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
                os_type: Os::Windows,
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
        let ctx = crate::ports::mock::create_test_context_with_hosts(hosts);
        let handler = SshServiceStatusHandler::new();
        let args = json!({"host": "winbox", "service": "nginx"});
        let result = handler.execute(Some(args), &ctx).await.unwrap();
        assert_eq!(result.is_error, Some(true));
    }

    // ============== Full Pipeline Test ==============

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType as Os};
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
                tags: Vec::new(),
                os_type: Os::default(),
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
        let handler = SshServiceStatusHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("nginx.service - Nginx\n   Loaded: loaded\n   Active: active (running)"),
        );
        let result = handler
            .execute(Some(json!({"host": "server1", "service": "nginx"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
