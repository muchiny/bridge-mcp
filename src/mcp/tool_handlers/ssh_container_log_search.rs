//! SSH Container Log Search Tool Handler
//!
//! Searches Docker or Podman container logs for a pattern on a remote host
//! via `docker logs ... | grep`. Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::container_logs::ContainerLogCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshContainerLogSearchArgs {
    host: String,
    container: String,
    pattern: String,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    tail: Option<u64>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshContainerLogSearchArgs);

#[mcp_standard_tool(
    name = "ssh_container_log_search",
    group = "container_logs",
    annotation = "read_only"
)]
pub struct ContainerLogSearchTool;

impl StandardTool for ContainerLogSearchTool {
    type Args = SshContainerLogSearchArgs;

    const NAME: &'static str = "ssh_container_log_search";

    const DESCRIPTION: &'static str = "Search container logs for a pattern on a remote host. \
        Filters Docker or Podman container logs by grep pattern with optional time range. \
        Use ssh_docker_ps first to find container names. Returns matching log lines (no context \
        window — grep -C is not available; use ssh_docker_logs for full log streaming).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "container": {
                "type": "string",
                "description": "Container name or ID to search logs in"
            },
            "pattern": {
                "type": "string",
                "description": "Grep pattern to search for in container logs (case-insensitive)"
            },
            "since": {
                "type": "string",
                "description": "Show logs since timestamp or relative time (e.g., 2024-01-01, 1h, 30m)"
            },
            "tail": {
                "type": "integer",
                "description": "Number of lines from the end to search (--tail=N, default: all). Primary output-reduction lever — always set this for large containers (e.g. tail=1000) before broadening the time window with `since`.",
                "minimum": 1
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
        "required": ["host", "container", "pattern"]
    }"#;

    fn build_command(
        args: &SshContainerLogSearchArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        Ok(ContainerLogCommandBuilder::build_log_search_command(
            args.docker_bin.as_deref(),
            &args.container,
            &args.pattern,
            args.since.as_deref(),
            args.tail,
        ))
    }

    fn validate(args: &SshContainerLogSearchArgs, _host_config: &HostConfig) -> Result<()> {
        ContainerLogCommandBuilder::validate_container_name(&args.container)?;
        ContainerLogCommandBuilder::validate_pattern(&args.pattern)?;
        Ok(())
    }
}

/// Handler for the `ssh_container_log_search` tool.
pub type SshContainerLogSearchHandler = StandardToolHandler<ContainerLogSearchTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshContainerLogSearchHandler::new();
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
        let handler = SshContainerLogSearchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "container": "nginx", "pattern": "error"})),
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
        let handler = SshContainerLogSearchHandler::new();
        assert_eq!(handler.name(), "ssh_container_log_search");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("container")));
        assert!(required.contains(&json!("pattern")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "container": "nginx",
            "pattern": "error",
            "since": "1h",
            "tail": 100,
            "docker_bin": "podman",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshContainerLogSearchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "nginx");
        assert_eq!(args.pattern, "error");
        assert_eq!(args.since, Some("1h".to_string()));
        assert_eq!(args.tail, Some(100));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "container": "web", "pattern": "timeout"});
        let args: SshContainerLogSearchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "web");
        assert_eq!(args.pattern, "timeout");
        assert!(args.since.is_none());
        assert!(args.tail.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshContainerLogSearchHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("since"));
        assert!(properties.contains_key("tail"));
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "container": "nginx", "pattern": "error"});
        let args: SshContainerLogSearchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshContainerLogSearchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshContainerLogSearchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "container": "nginx", "pattern": "error"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshContainerLogSearchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1", "container": "nginx"})), &ctx)
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
        let args = SshContainerLogSearchArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            pattern: "error".to_string(),
            since: None,
            tail: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = ContainerLogSearchTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker logs"));
        assert!(cmd.contains("nginx"));
        assert!(cmd.contains("grep -i"));
        assert!(cmd.contains("error"));
    }

    #[test]
    fn test_build_command_with_since_and_tail() {
        let args = SshContainerLogSearchArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            pattern: "timeout".to_string(),
            since: Some("1h".to_string()),
            tail: Some(200),
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = ContainerLogSearchTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("1h"));
        assert!(cmd.contains("--tail=200"));
    }

    #[test]
    fn test_validate_valid() {
        let args = SshContainerLogSearchArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            pattern: "error".to_string(),
            since: None,
            tail: None,
            docker_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(ContainerLogSearchTool::validate(&args, &test_host_config()).is_ok());
    }

    #[test]
    fn test_validate_bad_container() {
        let args = SshContainerLogSearchArgs {
            host: "server1".to_string(),
            container: "nginx; rm -rf /".to_string(),
            pattern: "error".to_string(),
            since: None,
            tail: None,
            docker_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(ContainerLogSearchTool::validate(&args, &test_host_config()).is_err());
    }

    #[test]
    fn test_validate_bad_pattern() {
        let args = SshContainerLogSearchArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            pattern: "error; rm -rf /".to_string(),
            since: None,
            tail: None,
            docker_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(ContainerLogSearchTool::validate(&args, &test_host_config()).is_err());
    }
}
