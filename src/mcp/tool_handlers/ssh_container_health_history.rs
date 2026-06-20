//! SSH Container Health History Tool Handler
//!
//! Shows health check history for a Docker container on a remote host.
//! Displays recent health check results including exit codes, output,
//! and timestamps. Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::container_logs::ContainerLogCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshContainerHealthHistoryArgs {
    host: String,
    container: String,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshContainerHealthHistoryArgs);

#[mcp_standard_tool(
    name = "ssh_container_health_history",
    group = "container_logs",
    annotation = "read_only"
)]
pub struct ContainerHealthHistoryTool;

impl StandardTool for ContainerHealthHistoryTool {
    type Args = SshContainerHealthHistoryArgs;

    const NAME: &'static str = "ssh_container_health_history";

    const DESCRIPTION: &'static str = "Show health check history for a Docker container on a \
        remote host. Returns JSON with shape {Status, FailingStreak, Log: [{Start, End, ExitCode, \
        Output}]}. Use ssh_docker_ps to find containers with health checks configured. To extract \
        only failures: pipe through jq_filter '.Log[] | select(.ExitCode != 0)'; for last 5 \
        checks use '.Log[-5:]'.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "container": {
                "type": "string",
                "description": "Container name or ID to check health history for"
            },
            "docker_bin": {
                "type": "string",
                "description": "Custom docker binary path (default: auto-detect docker or podman)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "container"]
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;

    fn build_command(
        args: &SshContainerHealthHistoryArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        Ok(ContainerLogCommandBuilder::build_health_history_command(
            args.docker_bin.as_deref(),
            &args.container,
        ))
    }

    fn validate(args: &SshContainerHealthHistoryArgs, _host_config: &HostConfig) -> Result<()> {
        ContainerLogCommandBuilder::validate_container_name(&args.container)?;
        Ok(())
    }
}

/// Handler for the `ssh_container_health_history` tool.
pub type SshContainerHealthHistoryHandler = StandardToolHandler<ContainerHealthHistoryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshContainerHealthHistoryHandler::new();
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
        let handler = SshContainerHealthHistoryHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "container": "nginx"})),
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
        let handler = SshContainerHealthHistoryHandler::new();
        assert_eq!(handler.name(), "ssh_container_health_history");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("container")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "container": "nginx",
            "docker_bin": "podman",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshContainerHealthHistoryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "nginx");
        assert_eq!(args.docker_bin, Some("podman".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "container": "web"});
        let args: SshContainerHealthHistoryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "web");
        assert!(args.docker_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshContainerHealthHistoryHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "container": "nginx"});
        let args: SshContainerHealthHistoryArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshContainerHealthHistoryArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshContainerHealthHistoryHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "container": "nginx"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshContainerHealthHistoryHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: AuthConfig::Agent,
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
        }
    }

    #[test]
    fn test_build_command_basic() {
        let args = SshContainerHealthHistoryArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = ContainerHealthHistoryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker inspect"));
        assert!(cmd.contains("State.Health"));
        assert!(cmd.contains("nginx"));
    }

    #[test]
    fn test_build_command_podman() {
        let args = SshContainerHealthHistoryArgs {
            host: "server1".to_string(),
            container: "webapp".to_string(),
            docker_bin: Some("podman".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = ContainerHealthHistoryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("podman inspect"));
        assert!(cmd.contains("webapp"));
    }

    #[test]
    fn test_validate_valid() {
        let args = SshContainerHealthHistoryArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            docker_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(ContainerHealthHistoryTool::validate(&args, &test_host_config()).is_ok());
    }

    #[test]
    fn test_validate_bad_container() {
        let args = SshContainerHealthHistoryArgs {
            host: "server1".to_string(),
            container: "nginx; rm -rf /".to_string(),
            docker_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(ContainerHealthHistoryTool::validate(&args, &test_host_config()).is_err());
    }
}
