//! SSH Docker Network Inspect Tool Handler
//!
//! Inspects a Docker network on a remote host via `docker network inspect`.
//! Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::docker::DockerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshDockerNetworkInspectArgs {
    host: String,
    network: String,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshDockerNetworkInspectArgs);

#[mcp_standard_tool(
    name = "ssh_docker_network_inspect",
    group = "docker",
    annotation = "read_only"
)]
pub struct DockerNetworkInspectTool;

impl StandardTool for DockerNetworkInspectTool {
    type Args = SshDockerNetworkInspectArgs;

    const NAME: &'static str = "ssh_docker_network_inspect";

    const DESCRIPTION: &'static str = "Inspect a Docker network on a remote host. Returns detailed JSON information about \
        the network including IPAM config, connected containers, and options. Use \
        ssh_docker_network_ls first to discover network names.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "network": {
                "type": "string",
                "description": "The Docker network name to inspect"
            },
            "format": {
                "type": "string",
                "description": "Output format using Go template (e.g., '{{.IPAM}}') or 'json'"
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
        "required": ["host", "network"]
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;

    fn build_command(
        args: &SshDockerNetworkInspectArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        Ok(DockerCommandBuilder::build_network_inspect_command(
            args.docker_bin.as_deref(),
            &args.network,
            args.format.as_deref(),
        ))
    }
}

/// Handler for the `ssh_docker_network_inspect` tool.
pub type SshDockerNetworkInspectHandler = StandardToolHandler<DockerNetworkInspectTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerNetworkInspectHandler::new();
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
        let handler = SshDockerNetworkInspectHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "network": "my-network"})),
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
        let handler = SshDockerNetworkInspectHandler::new();
        assert_eq!(handler.name(), "ssh_docker_network_inspect");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_docker_network_inspect");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("network")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "network": "my-network",
            "format": "json",
            "docker_bin": "podman",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/output.txt"
        });
        let args: SshDockerNetworkInspectArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.network, "my-network");
        assert_eq!(args.format, Some("json".to_string()));
        assert_eq!(args.docker_bin, Some("podman".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "network": "my-network"});
        let args: SshDockerNetworkInspectArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.network, "my-network");
        assert!(args.format.is_none());
        assert!(args.docker_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerNetworkInspectHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("format"));
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "network": "my-network"});
        let args: SshDockerNetworkInspectArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerNetworkInspectArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerNetworkInspectHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "network": "net"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_rate_limit_returns_error_result() {
        use crate::ports::mock::create_test_context_with_host;
        use crate::ports::protocol::ToolContent;
        use crate::security::RateLimiter;
        use std::sync::Arc;

        let handler = SshDockerNetworkInspectHandler::new();
        let mut ctx = create_test_context_with_host();
        ctx.rate_limiter = Arc::new(RateLimiter::new(1));

        // Exhaust the single token for server1
        assert!(ctx.rate_limiter.check("server1").is_ok());

        // Use explicit docker_bin to avoid auto-detect prefix with &>/dev/null
        // which triggers the blacklist pattern (?i)>\s*/dev/
        let result = handler
            .execute(
                Some(json!({"host": "server1", "network": "my-network", "docker_bin": "docker"})),
                &ctx,
            )
            .await;

        // Rate limit returns Ok with error content, not Err
        let result = result.unwrap();
        assert_eq!(result.is_error, Some(true));
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("Rate limit exceeded"));
                assert!(text.contains("server1"));
            }
            _ => panic!("Expected Text content"),
        }
    }
}
