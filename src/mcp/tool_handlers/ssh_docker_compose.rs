//! SSH Docker Compose Tool Handler
//!
//! Manages Docker Compose stacks on a remote host.
//! Supports actions: up, down, restart, ps, logs, pull, build.
//! Auto-detects `docker compose` v2 or `docker-compose` v1.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::docker::DockerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshDockerComposeArgs {
    host: String,
    action: String,
    project_dir: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    services: Option<Vec<String>>,
    #[serde(default)]
    detach: Option<bool>,
    #[serde(default)]
    build: Option<bool>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    compose_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshDockerComposeArgs);

#[mcp_standard_tool(
    name = "ssh_docker_compose",
    group = "docker",
    annotation = "destructive"
)]
pub struct DockerComposeTool;

impl StandardTool for DockerComposeTool {
    type Args = SshDockerComposeArgs;

    const NAME: &'static str = "ssh_docker_compose";

    const DESCRIPTION: &'static str = "Manage Docker Compose stacks on a remote host. Actions: up (start/create), down \
        (stop/remove), restart, ps (list services), logs (view output), pull (update images), \
        build (rebuild). Specify project_dir as the path containing docker-compose.yml. \
        Auto-detects docker compose v2 or docker-compose v1.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "action": {
                "type": "string",
                "enum": ["up", "down", "restart", "ps", "logs", "pull", "build"],
                "description": "Compose action to perform"
            },
            "project_dir": {
                "type": "string",
                "description": "Path to the directory containing docker-compose.yml on the remote host"
            },
            "file": {
                "type": "string",
                "description": "Alternative compose file name (default: docker-compose.yml)"
            },
            "services": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Specific services to target (default: all services)"
            },
            "detach": {
                "type": "boolean",
                "description": "Run in detached mode (for 'up' action only, default: true)"
            },
            "build": {
                "type": "boolean",
                "description": "Build images before starting (for 'up' action only)"
            },
            "timeout": {
                "type": "integer",
                "description": "Shutdown timeout in seconds (for 'down' and 'restart' actions)",
                "minimum": 0
            },
            "compose_bin": {
                "type": "string",
                "description": "Custom compose binary (default: auto-detect 'docker compose' v2 or 'docker-compose' v1)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional SSH command timeout in seconds (default: from config)",
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
        "required": ["host", "action", "project_dir"]
    }"#;

    fn validate(args: &SshDockerComposeArgs, _host_config: &HostConfig) -> Result<()> {
        DockerCommandBuilder::validate_compose_action(&args.action)
    }

    fn build_command(args: &SshDockerComposeArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_compose_command(
            args.compose_bin.as_deref(),
            &args.action,
            &args.project_dir,
            args.file.as_deref(),
            args.services.as_deref(),
            args.detach.unwrap_or(true),
            args.build.unwrap_or(false),
            args.timeout,
        ))
    }
}

/// Handler for the `ssh_docker_compose` tool.
pub type SshDockerComposeHandler = StandardToolHandler<DockerComposeTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerComposeHandler::new();
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
        let handler = SshDockerComposeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "action": "ps",
                    "project_dir": "/opt/app"
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_action() {
        let handler = SshDockerComposeHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "action": "rm",
                    "project_dir": "/opt/app"
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("rm"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshDockerComposeHandler::new();
        assert_eq!(handler.name(), "ssh_docker_compose");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("action")));
        assert!(required.contains(&json!("project_dir")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "action": "up",
            "project_dir": "/opt/app",
            "file": "docker-compose.prod.yml",
            "services": ["web", "redis"],
            "detach": true,
            "build": true,
            "timeout": 30,
            "compose_bin": "docker-compose",
            "timeout_seconds": 120,
            "max_output": 10000,
            "save_output": "/tmp/compose.log"
        });
        let args: SshDockerComposeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.action, "up");
        assert_eq!(args.project_dir, "/opt/app");
        assert_eq!(args.file, Some("docker-compose.prod.yml".to_string()));
        assert_eq!(
            args.services,
            Some(vec!["web".to_string(), "redis".to_string()])
        );
        assert_eq!(args.detach, Some(true));
        assert_eq!(args.build, Some(true));
        assert_eq!(args.timeout, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "action": "ps",
            "project_dir": "/opt/app"
        });
        let args: SshDockerComposeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.action, "ps");
        assert_eq!(args.project_dir, "/opt/app");
        assert!(args.file.is_none());
        assert!(args.services.is_none());
        assert!(args.detach.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshDockerComposeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1", "action": "up"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerComposeHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("file"));
        assert!(properties.contains_key("services"));
        assert!(properties.contains_key("detach"));
        assert!(properties.contains_key("build"));
        assert!(properties.contains_key("timeout"));
        assert!(properties.contains_key("compose_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "s1",
            "action": "ps",
            "project_dir": "/opt"
        });
        let args: SshDockerComposeArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerComposeArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerComposeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "action": "ps", "project_dir": "/opt"})),
                &ctx,
            )
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
        let args = SshDockerComposeArgs {
            host: "server1".to_string(),
            action: "up".to_string(),
            project_dir: "/app".to_string(),
            file: None,
            services: None,
            detach: None,
            build: None,
            timeout: None,
            compose_bin: Some("docker compose".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerComposeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker compose"));
        assert!(cmd.contains("up"));
        assert!(cmd.contains("/app"));
    }

    #[test]
    fn test_build_command_with_file() {
        let args = SshDockerComposeArgs {
            host: "server1".to_string(),
            action: "up".to_string(),
            project_dir: "/app".to_string(),
            file: Some("prod.yml".to_string()),
            services: None,
            detach: None,
            build: None,
            timeout: None,
            compose_bin: Some("docker compose".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerComposeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("prod.yml"));
    }

    #[test]
    fn test_build_command_with_services() {
        let args = SshDockerComposeArgs {
            host: "server1".to_string(),
            action: "up".to_string(),
            project_dir: "/app".to_string(),
            file: None,
            services: Some(vec!["web".to_string(), "db".to_string()]),
            detach: None,
            build: None,
            timeout: None,
            compose_bin: Some("docker compose".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerComposeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("web"));
        assert!(cmd.contains("db"));
    }

    #[test]
    fn test_build_command_all_options() {
        let args = SshDockerComposeArgs {
            host: "server1".to_string(),
            action: "up".to_string(),
            project_dir: "/app".to_string(),
            file: Some("prod.yml".to_string()),
            services: Some(vec!["web".to_string(), "db".to_string()]),
            detach: Some(false),
            build: Some(true),
            timeout: Some(30),
            compose_bin: Some("docker compose".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerComposeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker compose"));
        assert!(cmd.contains("prod.yml"));
        assert!(cmd.contains("web"));
        assert!(cmd.contains("db"));
        assert!(cmd.contains("--build"));
    }
}
