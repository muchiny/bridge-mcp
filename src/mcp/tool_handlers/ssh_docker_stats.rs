//! SSH Docker Stats Tool Handler
//!
//! Displays resource usage statistics of Docker containers on a remote host
//! via `docker stats`. Auto-detects `docker` or `podman` binary.

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
pub struct SshDockerStatsArgs {
    host: String,
    #[serde(default)]
    containers: Option<Vec<String>>,
    #[serde(default)]
    no_stream: Option<bool>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshDockerStatsArgs);

#[mcp_standard_tool(name = "ssh_docker_stats", group = "docker", annotation = "read_only")]
pub struct DockerStatsTool;

impl StandardTool for DockerStatsTool {
    type Args = SshDockerStatsArgs;

    const NAME: &'static str = "ssh_docker_stats";

    const DESCRIPTION: &'static str = "Display CPU, memory, network, and disk I/O usage of Docker containers on a remote \
        host. Shows all running containers by default or specify specific containers. Always \
        runs in one-shot mode (--no-stream) by default. For Kubernetes pod metrics, use \
        ssh_k8s_top instead. Auto-detects docker or podman.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "containers": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Specific container names or IDs to show stats for (default: all running)"
            },
            "no_stream": {
                "type": "boolean",
                "description": "Disable streaming and show one-shot stats (default: true for MCP usage)"
            },
            "format": {
                "type": "string",
                "description": "Output format using Go template (e.g., '{{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}')"
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
            }
        },
        "required": ["host"]
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshDockerStatsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_stats_command(
            args.docker_bin.as_deref(),
            args.containers.as_deref(),
            args.no_stream.unwrap_or(true),
            args.format.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshDockerStatsArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Docker Stats")
            .column("name", "Name")
            .column("cpu", "CPU %")
            .column("mem_usage", "Mem Usage")
            .column("mem_pct", "Mem %")
            .column("net_io", "Net I/O")
            .column("block_io", "Block I/O")
            .column("pids", "PIDs");

        let name_idx = parsed.headers.iter().position(|h| h == "name");
        let cpu_idx = parsed.headers.iter().position(|h| h == "cpu %");
        let mem_usage_idx = parsed
            .headers
            .iter()
            .position(|h| h.starts_with("mem usage"));
        let mem_pct_idx = parsed.headers.iter().position(|h| h == "mem %");
        let net_idx = parsed.headers.iter().position(|h| h == "net i/o");
        let block_idx = parsed.headers.iter().position(|h| h == "block i/o");
        let pids_idx = parsed.headers.iter().position(|h| h == "pids");

        for row in &parsed.rows {
            let get = |idx: Option<usize>| idx.and_then(|i| row.get(i)).map_or("", String::as_str);
            // `docker stats` emits NAME as the second column (after CONTAINER
            // ID). Recover it positionally if the header lookup missed, rather
            // than dropping every row.
            let name = match name_idx {
                Some(i) => row.get(i).map_or("", String::as_str),
                None => row.get(1).map_or("", String::as_str),
            };
            if !name.is_empty() {
                tbl = tbl
                    .row(json!({
                        "name": name,
                        "cpu": get(cpu_idx),
                        "mem_usage": get(mem_usage_idx),
                        "mem_pct": get(mem_pct_idx),
                        "net_io": get(net_idx),
                        "block_io": get(block_idx),
                        "pids": get(pids_idx),
                    }))
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
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_docker_stats` tool.
pub type SshDockerStatsHandler = StandardToolHandler<DockerStatsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerStatsHandler::new();
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
        let handler = SshDockerStatsHandler::new();
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
        let handler = SshDockerStatsHandler::new();
        assert_eq!(handler.name(), "ssh_docker_stats");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_docker_stats");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "containers": ["web", "db"],
            "no_stream": true,
            "format": "{{.Name}}\t{{.CPUPerc}}",
            "docker_bin": "podman",
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshDockerStatsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(
            args.containers,
            Some(vec!["web".to_string(), "db".to_string()])
        );
        assert_eq!(args.no_stream, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshDockerStatsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.containers.is_none());
        assert!(args.no_stream.is_none());
        assert!(args.format.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerStatsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("containers"));
        assert!(properties.contains_key("no_stream"));
        assert!(properties.contains_key("format"));
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshDockerStatsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerStatsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerStatsHandler::new();
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
        let args = SshDockerStatsArgs {
            host: "server1".to_string(),
            containers: None,
            no_stream: None,
            format: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerStatsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker stats"));
        assert!(cmd.contains("--no-stream"));
    }

    #[test]
    fn test_build_command_with_containers() {
        let args = SshDockerStatsArgs {
            host: "server1".to_string(),
            containers: Some(vec!["web".to_string(), "db".to_string()]),
            no_stream: None,
            format: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerStatsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("web"));
        assert!(cmd.contains("db"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshDockerStatsArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "NAME  CPU %   MEM USAGE / LIMIT   MEM %   NET I/O       BLOCK I/O     PIDS\nweb   0.50%   50MiB / 1GiB        5.00%   1.2kB / 0B    0B / 0B       5\ndb    1.20%   200MiB / 2GiB       10.00%  5kB / 1kB     10MB / 5MB    12\n";
        let result = DockerStatsTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshDockerStatsArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = DockerStatsTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_build_command_no_stream_format() {
        let args = SshDockerStatsArgs {
            host: "server1".to_string(),
            containers: None,
            no_stream: Some(false),
            format: Some("json".to_string()),
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerStatsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(!cmd.contains("--no-stream"));
        assert!(cmd.contains("json"));
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
        let handler = SshDockerStatsHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "NAME  CPU %   MEM USAGE / LIMIT   MEM %   NET I/O       BLOCK I/O     PIDS\nweb   0.50%   50MiB / 1GiB        5.00%   1.2kB / 0B    0B / 0B       5\n",
            ),
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
