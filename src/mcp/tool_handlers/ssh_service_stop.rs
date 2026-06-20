//! Handler for the `ssh_service_stop` tool.
//!
//! Stops a systemd service on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::systemd::{SystemdCommandBuilder, validate_service_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshServiceStopArgs {
    host: String,
    service: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshServiceStopArgs);

#[mcp_standard_tool(
    name = "ssh_service_stop",
    group = "systemd",
    annotation = "destructive"
)]
pub struct ServiceStopTool;

impl StandardTool for ServiceStopTool {
    type Args = SshServiceStopArgs;

    const NAME: &'static str = "ssh_service_stop";

    const DESCRIPTION: &'static str = "Stop a systemd service on a remote host (systemctl stop). Prefer this over \
        ssh_exec as it validates the service name. Requires root/sudo permissions. \
        This is a destructive operation — a confirmation elicitation is sent before \
        executing when the client supports it. This only stops the service for the \
        current session; to also disable it on boot use ssh_service_disable. \
        Check result with ssh_service_status afterward. \
        For Windows hosts use ssh_win_service_stop instead.";

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
                "description": "Name of the systemd service to stop (e.g., nginx, sshd, docker)"
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

    fn build_command(args: &SshServiceStopArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SystemdCommandBuilder::build_stop_command(&args.service))
    }

    fn validate(args: &SshServiceStopArgs, _host_config: &HostConfig) -> Result<()> {
        validate_service_name(&args.service)?;
        Ok(())
    }

    /// Confirm destructive operation via `elicitation/create` before
    /// running the underlying command. Falls back to a no-op when the
    /// client does not advertise the elicitation capability — the
    /// global `security.require_elicitation_on_destructive` gate still
    /// applies in that case.
    async fn pre_execute(args: &Self::Args, ctx: &ToolContext) -> Result<Option<ToolCallResult>> {
        let summary = format!(
            "Stop systemd service `{}` on host `{}`",
            args.service, args.host,
        );
        match ctx.elicit_confirm(Self::NAME, &summary).await? {
            Some(false) => Ok(Some(ToolCallResult::error(
                "User declined destructive operation".to_string(),
            ))),
            _ => Ok(None),
        }
    }
}

/// Handler for the `ssh_service_stop` tool.
pub type SshServiceStopHandler = StandardToolHandler<ServiceStopTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshServiceStopHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshServiceStopHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "service": "nginx"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshServiceStopHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_service_stop");
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
        let args: SshServiceStopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "service": "nginx"});
        let args: SshServiceStopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshServiceStopHandler::new();
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
        let args: SshServiceStopArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshServiceStopArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "service": "nginx"});
        let result = serde_json::from_value::<SshServiceStopArgs>(json);
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
        let args: SshServiceStopArgs =
            serde_json::from_value(json!({"host": "s", "service": "nginx"})).unwrap();
        let host = test_host_config();
        let cmd = ServiceStopTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("nginx"));
    }
}
