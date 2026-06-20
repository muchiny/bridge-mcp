//! SSH Docker Ps Tool Handler
//!
//! Lists Docker containers on a remote host via `docker ps`.
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
pub struct SshDockerPsArgs {
    host: String,
    #[serde(default)]
    all: Option<bool>,
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

impl_common_args!(SshDockerPsArgs);

#[mcp_standard_tool(name = "ssh_docker_ps", group = "docker", annotation = "read_only")]
pub struct DockerPsTool;

impl StandardTool for DockerPsTool {
    type Args = SshDockerPsArgs;

    const NAME: &'static str = "ssh_docker_ps";

    const DESCRIPTION: &'static str = "List Docker containers on a remote host. Start here to discover container names \
        before using ssh_docker_inspect (detailed config), ssh_docker_logs (output), \
        ssh_docker_exec (run commands inside), or ssh_docker_stats (resource usage). Shows \
        running containers by default; set all=true to include stopped. Auto-detects docker \
        or podman binary. To view real-time Docker daemon events (container start/stop/die), \
        use ssh_container_events.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "all": {
                "type": "boolean",
                "description": "Show all containers including stopped ones (docker ps -a)"
            },
            "filter": {
                "type": "string",
                "description": "Filter by condition (e.g., status=running, name=nginx, label=env=prod)"
            },
            "format": {
                "type": "string",
                "description": "Output format using Go template (e.g., '{{.Names}}\\t{{.Status}}') or 'json'"
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

    fn build_command(args: &SshDockerPsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_ps_command(
            args.docker_bin.as_deref(),
            args.all.unwrap_or(false),
            args.filter.as_deref(),
            args.format.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshDockerPsArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Docker Containers")
            .column("name", "Name")
            .column("image", "Image")
            .column("status", "Status")
            .column("ports", "Ports");

        let name_idx = parsed.headers.iter().position(|h| h == "names");
        let image_idx = parsed.headers.iter().position(|h| h == "image");
        let status_idx = parsed.headers.iter().position(|h| h == "status");
        let ports_idx = parsed.headers.iter().position(|h| h == "ports");

        for row in &parsed.rows {
            let get = |idx: Option<usize>| idx.and_then(|i| row.get(i)).map_or("", String::as_str);
            // `docker ps` always emits NAMES as the final column. If the header
            // lookup missed (e.g. a wide image/name merged columns in the
            // space-gutter parser), recover the name positionally rather than
            // dropping every row.
            let name = match name_idx {
                Some(i) => row.get(i).map_or("", String::as_str),
                None => row.last().map_or("", String::as_str),
            };
            let image = get(image_idx);
            let status = get(status_idx);
            let ports = get(ports_idx);

            if !name.is_empty() {
                tbl = tbl
                    .row(json!({"name": name, "image": image, "status": status, "ports": ports}))
                    .action(
                        format!("logs-{name}"),
                        format!("Logs {name}"),
                        "ssh_docker_logs",
                        Some(json!({"host": args.host, "container": name})),
                    )
                    .action(
                        format!("inspect-{name}"),
                        format!("Inspect {name}"),
                        "ssh_docker_inspect",
                        Some(json!({"host": args.host, "container": name})),
                    );
            }
        }
        // Replace text with TSV for token efficiency
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_docker_ps` tool.
pub type SshDockerPsHandler = StandardToolHandler<DockerPsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerPsHandler::new();
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
        let handler = SshDockerPsHandler::new();
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
        let handler = SshDockerPsHandler::new();
        assert_eq!(handler.name(), "ssh_docker_ps");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_docker_ps");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "all": true,
            "filter": "status=running",
            "format": "json",
            "docker_bin": "podman",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/output.txt"
        });
        let args: SshDockerPsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.all, Some(true));
        assert_eq!(args.filter, Some("status=running".to_string()));
        assert_eq!(args.docker_bin, Some("podman".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshDockerPsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.all.is_none());
        assert!(args.filter.is_none());
        assert!(args.format.is_none());
        assert!(args.docker_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerPsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("all"));
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
        let args: SshDockerPsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerPsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerPsHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
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
        let args = SshDockerPsArgs {
            host: "server1".to_string(),
            all: None,
            filter: None,
            format: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerPsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker ps"));
    }

    #[test]
    fn test_build_command_all_flag() {
        let args = SshDockerPsArgs {
            host: "server1".to_string(),
            all: Some(true),
            filter: None,
            format: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerPsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-a"));
    }

    #[test]
    fn test_build_command_with_filter_format() {
        let args = SshDockerPsArgs {
            host: "server1".to_string(),
            all: None,
            filter: Some("status=running".to_string()),
            format: Some("json".to_string()),
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerPsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("status=running"));
        assert!(cmd.contains("json"));
    }

    #[test]
    fn test_build_command_custom_bin() {
        let args = SshDockerPsArgs {
            host: "server1".to_string(),
            all: None,
            filter: None,
            format: None,
            docker_bin: Some("podman".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerPsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.starts_with("podman"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshDockerPsArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "CONTAINER ID  IMAGE          COMMAND       CREATED       STATUS        PORTS      NAMES\nabc123        nginx:latest   nginx -g      2 hours ago   Up 2 hours    80/tcp     web\ndef456        redis:7        redis-server  3 hours ago   Up 3 hours    6379/tcp   cache\n";
        let result = DockerPsTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshDockerPsArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = DockerPsTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }

    #[tokio::test]
    async fn test_rate_limit_returns_error_result() {
        use crate::ports::mock::create_test_context_with_host;
        use crate::ports::protocol::ToolContent;
        use crate::security::RateLimiter;
        use std::sync::Arc;

        let handler = SshDockerPsHandler::new();
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
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
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
            },
        );
        hosts
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshDockerPsHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "CONTAINER ID   IMAGE    COMMAND   CREATED   STATUS    PORTS   NAMES\nabc123   nginx   \"nginx -g...\"   2h ago   Up 2h   80/tcp   web\n",
            ),
        );
        // Use explicit docker_bin to avoid auto-detect &>/dev/null blacklist
        let result = handler
            .execute(
                Some(json!({"host": "server1", "docker_bin": "docker"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        // post_process adds App content
        assert!(result.content.len() >= 2);
        assert!(result.structured_content.is_some());
    }
}
