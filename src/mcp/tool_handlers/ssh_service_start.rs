//! Handler for the `ssh_service_start` tool.
//!
//! Starts a systemd service on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::systemd::{SystemdCommandBuilder, validate_service_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshServiceStartArgs {
    host: String,
    service: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshServiceStartArgs);

#[mcp_standard_tool(name = "ssh_service_start", group = "systemd", annotation = "mutating")]
pub struct ServiceStartTool;

impl StandardTool for ServiceStartTool {
    type Args = SshServiceStartArgs;

    const NAME: &'static str = "ssh_service_start";

    const DESCRIPTION: &'static str = "Start a systemd service on a remote host (systemctl start). Prefer this over \
        ssh_exec as it validates the service name. Requires root/sudo permissions. \
        This only starts the service for the current session; to also enable it on boot \
        use ssh_service_enable. Check result with ssh_service_status afterward. \
        For Windows hosts use ssh_win_service_start instead.";

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
                "description": "Name of the systemd service to start (e.g., nginx, sshd, docker)"
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

    fn build_command(args: &SshServiceStartArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SystemdCommandBuilder::build_start_command(&args.service))
    }

    fn validate(args: &SshServiceStartArgs, _host_config: &HostConfig) -> Result<()> {
        validate_service_name(&args.service)?;
        Ok(())
    }
}

/// Handler for the `ssh_service_start` tool.
pub type SshServiceStartHandler = StandardToolHandler<ServiceStartTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshServiceStartHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshServiceStartHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "service": "nginx"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshServiceStartHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_service_start");
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
        let args: SshServiceStartArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "service": "nginx"});
        let args: SshServiceStartArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshServiceStartHandler::new();
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
        let args: SshServiceStartArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshServiceStartArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "service": "nginx"});
        let result = serde_json::from_value::<SshServiceStartArgs>(json);
        assert!(result.is_err());
    }

    // ============== Validation & OS guard ==============

    #[tokio::test]
    async fn test_invalid_service_name_rejected() {
        use crate::ports::mock::create_test_context_with_host;

        let handler = SshServiceStartHandler::new();
        let ctx = create_test_context_with_host();
        let args = json!({"host": "server1", "service": "../etc/passwd"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_service_name_with_semicolon_rejected() {
        use crate::ports::mock::create_test_context_with_host;

        let handler = SshServiceStartHandler::new();
        let ctx = create_test_context_with_host();
        let args = json!({"host": "server1", "service": "nginx; rm -rf /"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_os_guard_rejects_windows_host() {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        use crate::ports::mock::create_test_context_with_hosts;
        use crate::ports::protocol::ToolContent;
        use std::collections::HashMap;

        let mut hosts = HashMap::new();
        hosts.insert(
            "win-server".to_string(),
            HostConfig {
                hostname: "192.168.1.200".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
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

        let handler = SshServiceStartHandler::new();
        let ctx = create_test_context_with_hosts(hosts);
        let args = json!({"host": "win-server", "service": "nginx"});
        let result = handler.execute(Some(args), &ctx).await.unwrap();
        assert_eq!(result.is_error, Some(true));
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("not available on Windows"));
            }
            _ => panic!("Expected Text content"),
        }
    }

    #[tokio::test]
    async fn test_rate_limit_returns_error_result() {
        use crate::ports::mock::create_test_context_with_host;
        use crate::ports::protocol::ToolContent;
        use crate::security::RateLimiter;
        use std::sync::Arc;

        let handler = SshServiceStartHandler::new();
        let mut ctx = create_test_context_with_host();
        ctx.rate_limiter = Arc::new(RateLimiter::new(1));

        assert!(ctx.rate_limiter.check("server1").is_ok());

        let args = json!({"host": "server1", "service": "nginx"});
        let result = handler.execute(Some(args), &ctx).await.unwrap();
        assert_eq!(result.is_error, Some(true));
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("Rate limit exceeded"));
            }
            _ => panic!("Expected Text content"),
        }
    }
}
