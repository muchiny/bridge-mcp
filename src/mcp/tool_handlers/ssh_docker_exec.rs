//! SSH Docker Exec Tool Handler
//!
//! Executes a command inside a running Docker container on a remote host
//! via `docker exec`. Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::docker::DockerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshDockerExecArgs {
    host: String,
    container: String,
    command: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    workdir: Option<String>,
    #[serde(default)]
    env: Option<Vec<String>>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshDockerExecArgs);

#[mcp_standard_tool(name = "ssh_docker_exec", group = "docker", annotation = "mutating")]
pub struct DockerExecTool;

impl StandardTool for DockerExecTool {
    type Args = SshDockerExecArgs;

    const NAME: &'static str = "ssh_docker_exec";

    const DESCRIPTION: &'static str = "Execute a command inside a running Docker container on a remote host. Use \
        ssh_docker_ps first to find container names. Supports custom user, working directory, \
        and environment variables. Auto-detects docker or podman. Returns command \
        stdout/stderr.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "container": {
                "type": "string",
                "description": "Container name or ID to execute the command in"
            },
            "command": {
                "type": "string",
                "description": "Command to execute inside the container (e.g., 'ls -la /app', 'cat /etc/hostname')"
            },
            "user": {
                "type": "string",
                "description": "Run command as this user inside the container (e.g., 'root', 'www-data')"
            },
            "workdir": {
                "type": "string",
                "description": "Working directory inside the container"
            },
            "env": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Environment variables to set (format: KEY=VALUE)"
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
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "container", "command"]
    }"#;

    fn build_command(args: &SshDockerExecArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_exec_command(
            args.docker_bin.as_deref(),
            &args.container,
            &args.command,
            args.user.as_deref(),
            args.workdir.as_deref(),
            args.env.as_deref(),
        ))
    }
}

/// Handler for the `ssh_docker_exec` tool.
pub type SshDockerExecHandler = StandardToolHandler<DockerExecTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerExecHandler::new();
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
        let handler = SshDockerExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "container": "app", "command": "ls"})),
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
        let handler = SshDockerExecHandler::new();
        assert_eq!(handler.name(), "ssh_docker_exec");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("container")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "container": "app",
            "command": "ls -la /app",
            "user": "root",
            "workdir": "/app",
            "env": ["FOO=bar", "DEBUG=1"],
            "docker_bin": "podman",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshDockerExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "app");
        assert_eq!(args.command, "ls -la /app");
        assert_eq!(args.user, Some("root".to_string()));
        assert_eq!(
            args.env,
            Some(vec!["FOO=bar".to_string(), "DEBUG=1".to_string()])
        );
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "container": "app", "command": "ls"});
        let args: SshDockerExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "app");
        assert_eq!(args.command, "ls");
        assert!(args.user.is_none());
        assert!(args.workdir.is_none());
        assert!(args.env.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshDockerExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1", "container": "app"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerExecHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("user"));
        assert!(properties.contains_key("workdir"));
        assert!(properties.contains_key("env"));
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "s1", "container": "app", "command": "ls"});
        let args: SshDockerExecArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerExecArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "container": "app", "command": "ls"})),
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
        let args = SshDockerExecArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            command: "ls".to_string(),
            user: None,
            workdir: None,
            env: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerExecTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker exec"));
        assert!(cmd.contains("nginx"));
        assert!(cmd.contains("ls"));
    }

    #[test]
    fn test_build_command_with_user_workdir() {
        let args = SshDockerExecArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            command: "ls".to_string(),
            user: Some("root".to_string()),
            workdir: Some("/app".to_string()),
            env: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerExecTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("root"));
        assert!(cmd.contains("/app"));
    }

    #[test]
    fn test_build_command_with_env() {
        let args = SshDockerExecArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            command: "ls".to_string(),
            user: None,
            workdir: None,
            env: Some(vec!["FOO=bar".to_string()]),
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerExecTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("FOO=bar"));
    }

    #[test]
    fn test_build_command_custom_bin() {
        let args = SshDockerExecArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            command: "ls".to_string(),
            user: None,
            workdir: None,
            env: None,
            docker_bin: Some("podman".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerExecTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("podman"));
    }
}
