//! SSH Docker Volume Ls Tool Handler
//!
//! Lists Docker volumes on a remote host via `docker volume ls`.
//! Auto-detects `docker` or `podman` binary.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::docker::DockerCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshDockerVolumeLsArgs {
    host: String,
    #[serde(default)]
    filter: Option<String>,
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

impl_common_args!(SshDockerVolumeLsArgs);

#[mcp_standard_tool(
    name = "ssh_docker_volume_ls",
    group = "docker",
    annotation = "read_only"
)]
pub struct DockerVolumeLsTool;

impl StandardTool for DockerVolumeLsTool {
    type Args = SshDockerVolumeLsArgs;

    const NAME: &'static str = "ssh_docker_volume_ls";

    const DESCRIPTION: &'static str = "List Docker volumes on a remote host. Shows volume names and drivers only \
        (DRIVER and VOLUME NAME columns). To get mount point, labels, and options use \
        ssh_docker_volume_inspect. Use filter to narrow results (e.g., dangling=true). \
        Auto-detects docker or podman binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "filter": {
                "type": "string",
                "description": "Filter by condition (e.g., dangling=true, driver=local, name=myvolume)"
            },
            "format": {
                "type": "string",
                "description": "Output format using Go template (e.g., '{{.Name}}\\t{{.Driver}}') or 'json'"
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
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshDockerVolumeLsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_volume_ls_command(
            args.docker_bin.as_deref(),
            args.filter.as_deref(),
            args.format.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshDockerVolumeLsArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Docker Volumes");
        for h in &parsed.headers {
            tbl = tbl.column(h, h.to_uppercase());
        }
        for row in &parsed.rows {
            let first = row.first().map_or("", String::as_str);
            if first.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            for (i, h) in parsed.headers.iter().enumerate() {
                obj.insert(
                    h.clone(),
                    serde_json::Value::String(row.get(i).map_or_else(String::new, Clone::clone)),
                );
            }
            tbl = tbl.row(serde_json::Value::Object(obj));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_docker_volume_ls",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_docker_volume_ls` tool.
pub type SshDockerVolumeLsHandler = StandardToolHandler<DockerVolumeLsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerVolumeLsHandler::new();
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
        let handler = SshDockerVolumeLsHandler::new();
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
        let handler = SshDockerVolumeLsHandler::new();
        assert_eq!(handler.name(), "ssh_docker_volume_ls");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_docker_volume_ls");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "filter": "dangling=true",
            "format": "json",
            "docker_bin": "podman",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/output.txt"
        });
        let args: SshDockerVolumeLsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.filter, Some("dangling=true".to_string()));
        assert_eq!(args.format, Some("json".to_string()));
        assert_eq!(args.docker_bin, Some("podman".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshDockerVolumeLsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.filter.is_none());
        assert!(args.format.is_none());
        assert!(args.docker_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerVolumeLsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("filter"));
        assert!(properties.contains_key("format"));
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshDockerVolumeLsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerVolumeLsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerVolumeLsHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command & post_process Tests ==============

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
        let args: SshDockerVolumeLsArgs =
            serde_json::from_value(json!({"host": "s", "docker_bin": "docker"})).unwrap();
        let host = test_host_config();
        let cmd = DockerVolumeLsTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("docker volume ls"));
    }

    #[test]
    fn test_build_command_with_filter_format() {
        let args: SshDockerVolumeLsArgs = serde_json::from_value(json!({
            "host": "s",
            "filter": "dangling=true",
            "format": "json",
            "docker_bin": "docker"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = DockerVolumeLsTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("dangling=true"));
        assert!(cmd.contains("json"));
    }

    #[test]
    fn test_build_command_custom_bin() {
        let args: SshDockerVolumeLsArgs =
            serde_json::from_value(json!({"host": "s", "docker_bin": "podman"})).unwrap();
        let host = test_host_config();
        let cmd = DockerVolumeLsTool::build_command(&args, &host).unwrap();
        assert!(cmd.starts_with("podman"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshDockerVolumeLsArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "DRIVER  VOLUME NAME\nlocal   my_volume\nlocal   db_data\n";
        let result = DockerVolumeLsTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshDockerVolumeLsArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = DockerVolumeLsTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }

    #[tokio::test]
    async fn test_rate_limit_returns_error_result() {
        use crate::ports::mock::create_test_context_with_host;
        use crate::ports::protocol::ToolContent;
        use crate::security::RateLimiter;
        use std::sync::Arc;

        let handler = SshDockerVolumeLsHandler::new();
        let mut ctx = create_test_context_with_host();
        ctx.rate_limiter = Arc::new(RateLimiter::new(1));

        // Exhaust the single token for server1
        assert!(ctx.rate_limiter.check("server1").is_ok());

        // Use explicit docker_bin to avoid auto-detect prefix with &>/dev/null
        // which triggers the blacklist pattern (?i)>\s*/dev/
        let result = handler
            .execute(
                Some(json!({"host": "server1", "docker_bin": "docker"})),
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
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            crate::config::HostConfig {
                hostname: "192.168.1.100".to_string(),
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
            },
        );
        hosts
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshDockerVolumeLsHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("DRIVER  VOLUME NAME\nlocal   my_volume\nlocal   db_data\n"),
        );
        let result = handler
            .execute(
                Some(json!({"host": "server1", "docker_bin": "docker"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        assert!(result.content.len() >= 2);
        assert!(result.structured_content.is_some());
    }
}
