//! SSH Container Events Tool Handler
//!
//! Shows Docker daemon events on a remote host. Displays container lifecycle
//! events like start, stop, die, restart, OOM kills, and health check failures.
//! Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::container_logs::ContainerLogCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshContainerEventsArgs {
    host: String,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshContainerEventsArgs);

#[mcp_standard_tool(
    name = "ssh_container_events",
    group = "container_logs",
    annotation = "read_only"
)]
pub struct ContainerEventsTool;

impl StandardTool for ContainerEventsTool {
    type Args = SshContainerEventsArgs;

    const NAME: &'static str = "ssh_container_events";

    const DESCRIPTION: &'static str = "Show Docker daemon events on a remote host. Displays \
        container lifecycle events like start, stop, die, restart, OOM kills, and health check \
        failures. Filter by event_type (container/image/network/volume only — daemon, service, \
        plugin, and Swarm node/secret/config types are not supported by this tool). \
        For full log streaming from a specific container use ssh_docker_logs; to search \
        container logs by pattern use ssh_container_log_search.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "since": {
                "type": "string",
                "description": "Show events since timestamp or relative time (default: 1h)"
            },
            "until": {
                "type": "string",
                "description": "Show events until timestamp or relative time (default: now)"
            },
            "event_type": {
                "type": "string",
                "description": "Filter by event type. Supported: container, image, network, volume. Docker's daemon/plugin/service/node/secret/config types are not accepted by this tool's validator.",
                "enum": ["container", "image", "network", "volume"]
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
        "required": ["host"]
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;

    fn build_command(args: &SshContainerEventsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(ContainerLogCommandBuilder::build_events_command(
            args.docker_bin.as_deref(),
            args.since.as_deref(),
            args.until.as_deref(),
            args.event_type.as_deref(),
        ))
    }

    fn validate(args: &SshContainerEventsArgs, _host_config: &HostConfig) -> Result<()> {
        if let Some(ref et) = args.event_type {
            ContainerLogCommandBuilder::validate_event_type(et)?;
        }
        Ok(())
    }
}

/// Handler for the `ssh_container_events` tool.
pub type SshContainerEventsHandler = StandardToolHandler<ContainerEventsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshContainerEventsHandler::new();
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
        let handler = SshContainerEventsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshContainerEventsHandler::new();
        assert_eq!(handler.name(), "ssh_container_events");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "since": "2h",
            "until": "30m",
            "event_type": "container",
            "docker_bin": "podman",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshContainerEventsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.since, Some("2h".to_string()));
        assert_eq!(args.until, Some("30m".to_string()));
        assert_eq!(args.event_type, Some("container".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshContainerEventsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.since.is_none());
        assert!(args.until.is_none());
        assert!(args.event_type.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshContainerEventsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("since"));
        assert!(properties.contains_key("until"));
        assert!(properties.contains_key("event_type"));
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshContainerEventsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshContainerEventsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshContainerEventsHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
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
    fn test_build_command_defaults() {
        let args = SshContainerEventsArgs {
            host: "server1".to_string(),
            since: None,
            until: None,
            event_type: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = ContainerEventsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker events"));
        assert!(cmd.contains("1h"));
        assert!(cmd.contains("now"));
        assert!(cmd.contains("json"));
    }

    #[test]
    fn test_build_command_with_type_filter() {
        let args = SshContainerEventsArgs {
            host: "server1".to_string(),
            since: Some("30m".to_string()),
            until: Some("10m".to_string()),
            event_type: Some("container".to_string()),
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = ContainerEventsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--filter type="));
        assert!(cmd.contains("container"));
        assert!(cmd.contains("30m"));
        assert!(cmd.contains("10m"));
    }

    #[test]
    fn test_validate_valid_event_type() {
        let args = SshContainerEventsArgs {
            host: "server1".to_string(),
            since: None,
            until: None,
            event_type: Some("container".to_string()),
            docker_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(ContainerEventsTool::validate(&args, &test_host_config()).is_ok());
    }

    #[test]
    fn test_validate_invalid_event_type() {
        let args = SshContainerEventsArgs {
            host: "server1".to_string(),
            since: None,
            until: None,
            event_type: Some("daemon".to_string()),
            docker_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(ContainerEventsTool::validate(&args, &test_host_config()).is_err());
    }

    #[test]
    fn test_validate_no_event_type() {
        let args = SshContainerEventsArgs {
            host: "server1".to_string(),
            since: None,
            until: None,
            event_type: None,
            docker_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(ContainerEventsTool::validate(&args, &test_host_config()).is_ok());
    }
}
