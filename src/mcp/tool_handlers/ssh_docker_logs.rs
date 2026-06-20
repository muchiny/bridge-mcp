//! SSH Docker Logs Tool Handler
//!
//! Fetches logs from a Docker container on a remote host via `docker logs`.
//! Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::docker::DockerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshDockerLogsArgs {
    host: String,
    container: String,
    #[serde(default)]
    tail: Option<u64>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    timestamps: Option<bool>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshDockerLogsArgs);

#[mcp_standard_tool(name = "ssh_docker_logs", group = "docker", annotation = "read_only")]
pub struct DockerLogsTool;

impl StandardTool for DockerLogsTool {
    type Args = SshDockerLogsArgs;

    const NAME: &'static str = "ssh_docker_logs";

    const DESCRIPTION: &'static str = "Fetch logs from a Docker container on a remote host. Use ssh_docker_ps first to find \
        container names. Supports tail (last N lines), since/until time-based filtering, and \
        timestamps. Auto-detects docker or podman binary. Returns log text. To search logs by \
        pattern use ssh_container_log_search; for log statistics use ssh_container_log_stats.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "container": {
                "type": "string",
                "description": "Container name or ID to fetch logs from"
            },
            "tail": {
                "type": "integer",
                "description": "Number of lines from the end (--tail=N, default: all)",
                "minimum": 1
            },
            "since": {
                "type": "string",
                "description": "Show logs since RFC3339 timestamp (e.g., 2024-01-01T00:00:00Z) or relative duration (1h, 30m, 2h30m)"
            },
            "until": {
                "type": "string",
                "description": "Show logs before timestamp or relative time"
            },
            "timestamps": {
                "type": "boolean",
                "description": "Include timestamps in log output (--timestamps)"
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

    fn build_command(args: &SshDockerLogsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_logs_command(
            args.docker_bin.as_deref(),
            &args.container,
            args.tail,
            args.since.as_deref(),
            args.until.as_deref(),
            args.timestamps.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_docker_logs` tool.
pub type SshDockerLogsHandler = StandardToolHandler<DockerLogsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerLogsHandler::new();
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
        let handler = SshDockerLogsHandler::new();
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
        let handler = SshDockerLogsHandler::new();
        assert_eq!(handler.name(), "ssh_docker_logs");
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
            "tail": 100,
            "since": "1h",
            "until": "30m",
            "timestamps": true,
            "docker_bin": "podman",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshDockerLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "nginx");
        assert_eq!(args.tail, Some(100));
        assert_eq!(args.since, Some("1h".to_string()));
        assert_eq!(args.timestamps, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "container": "web"});
        let args: SshDockerLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "web");
        assert!(args.tail.is_none());
        assert!(args.since.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshDockerLogsHandler::new();
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

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerLogsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("tail"));
        assert!(properties.contains_key("since"));
        assert!(properties.contains_key("until"));
        assert!(properties.contains_key("timestamps"));
        assert!(properties.contains_key("docker_bin"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "container": "nginx"});
        let args: SshDockerLogsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerLogsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerLogsHandler::new();
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

    // ============== build_command Tests ==============

    use crate::config::{HostConfig, HostKeyVerification, OsType};

    fn test_host_config() -> HostConfig {
        HostConfig {
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
        }
    }

    #[test]
    fn test_build_command_defaults() {
        let args = SshDockerLogsArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            tail: None,
            since: None,
            until: None,
            timestamps: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerLogsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker logs"));
        assert!(cmd.contains("nginx"));
    }

    #[test]
    fn test_build_command_with_tail_since() {
        let args = SshDockerLogsArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            tail: Some(100),
            since: Some("1h".to_string()),
            until: None,
            timestamps: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerLogsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("100"));
        assert!(cmd.contains("1h"));
    }

    #[test]
    fn test_build_command_with_timestamps() {
        let args = SshDockerLogsArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            tail: None,
            since: None,
            until: None,
            timestamps: Some(true),
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerLogsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--timestamps"));
    }

    #[test]
    fn test_build_command_all_flags() {
        let args = SshDockerLogsArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            tail: Some(50),
            since: Some("2h".to_string()),
            until: Some("1h".to_string()),
            timestamps: Some(true),
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerLogsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("50"));
        assert!(cmd.contains("2h"));
        assert!(cmd.contains("1h"));
        assert!(cmd.contains("--timestamps"));
    }
}
