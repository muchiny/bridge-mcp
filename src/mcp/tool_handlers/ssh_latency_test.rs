//! Handler for the `ssh_latency_test` tool.
//!
//! Tests network latency from a remote host to a target.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::performance::PerformanceCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_latency_test` tool.
#[derive(Debug, Deserialize)]
pub struct SshLatencyTestArgs {
    host: String,
    target: String,
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshLatencyTestArgs);

#[mcp_standard_tool(
    name = "ssh_latency_test",
    group = "performance",
    annotation = "read_only"
)]
pub struct LatencyTestTool;

impl StandardTool for LatencyTestTool {
    type Args = SshLatencyTestArgs;

    const NAME: &'static str = "ssh_latency_test";

    const DESCRIPTION: &'static str = "Test network latency from a Linux host to a target \
        hostname or IP. Uses ping (default) or mtr for round-trip time, packet loss, and hop \
        routing. Count is capped at 100 packets. For CPU/syscall profiling use ssh_perf_trace; \
        for disk I/O tracing use ssh_io_trace; for throughput benchmarks use ssh_benchmark. \
        For Windows network diagnostics use ssh_win_net_ping instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "target"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "target": {
                "type": "string",
                "description": "Target hostname or IP address (IPv4, IPv6, or DNS name). Only alphanumeric, dots, hyphens, colons, and underscores are allowed — no shell metacharacters."
            },
            "count": {
                "type": "integer",
                "description": "Number of packets to send (default: 5, max: 100)",
                "minimum": 1,
                "maximum": 100
            },
            "method": {
                "type": "string",
                "description": "Method to use: 'ping' (default) or 'mtr'",
                "enum": ["ping", "mtr"]
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the remote host"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshLatencyTestArgs, _host_config: &HostConfig) -> Result<String> {
        PerformanceCommandBuilder::build_latency_test_command(
            &args.target,
            args.count.unwrap_or(5),
            args.method.as_deref(),
        )
    }

    fn validate(args: &SshLatencyTestArgs, _host_config: &HostConfig) -> Result<()> {
        PerformanceCommandBuilder::validate_count(args.count.unwrap_or(5))?;
        crate::domain::use_cases::performance::validate_latency_target(&args.target)?;
        Ok(())
    }
}

/// Handler for the `ssh_latency_test` tool.
pub type SshLatencyTestHandler = StandardToolHandler<LatencyTestTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLatencyTestHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshLatencyTestHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "target": "8.8.8.8"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshLatencyTestHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_latency_test");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("target")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "myhost", "target": "8.8.8.8", "count": 10, "method": "mtr"});
        let args: SshLatencyTestArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "8.8.8.8");
        assert_eq!(args.count, Some(10));
        assert_eq!(args.method.as_deref(), Some("mtr"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "target": "example.com"});
        let args: SshLatencyTestArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "example.com");
        assert!(args.count.is_none());
        assert!(args.method.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshLatencyTestHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("target"));
        assert!(props.contains_key("count"));
        assert!(props.contains_key("method"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "target": "t"});
        let args: SshLatencyTestArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshLatencyTestArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "target": "x"});
        let result = serde_json::from_value::<SshLatencyTestArgs>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "server1",
            "target": "10.0.0.1",
            "count": 20,
            "method": "ping",
            "timeout_seconds": 120,
            "max_output": 10000,
            "save_output": "/tmp/latency.txt"
        });
        let args: SshLatencyTestArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target, "10.0.0.1");
        assert_eq!(args.count, Some(20));
        assert_eq!(args.method.as_deref(), Some("ping"));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/latency.txt"));
    }

    #[test]
    fn test_schema_method_enum() {
        let handler = SshLatencyTestHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let method = &schema_json["properties"]["method"];
        let enum_values = method["enum"].as_array().unwrap();
        assert!(enum_values.contains(&json!("ping")));
        assert!(enum_values.contains(&json!("mtr")));
    }

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
        let args: SshLatencyTestArgs =
            serde_json::from_value(json!({"host": "s", "target": "8.8.8.8"})).unwrap();
        let host = test_host_config();
        let cmd = LatencyTestTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("8.8.8.8"));
    }

    #[test]
    fn test_build_command_mtr() {
        let args: SshLatencyTestArgs = serde_json::from_value(json!({
            "host": "s", "target": "example.com", "method": "mtr", "count": 10
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = LatencyTestTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("mtr"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshLatencyTestArgs =
            serde_json::from_value(json!({"host": "s", "target": "8.8.8.8"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "PING 8.8.8.8: 64 bytes, time=10ms\n--- statistics ---\n5 packets, 0% loss\n";
        let result = LatencyTestTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshLatencyTestArgs =
            serde_json::from_value(json!({"host": "s", "target": "8.8.8.8"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = LatencyTestTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }

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

    fn pipeline_ctx(output: crate::ssh::CommandOutput) -> crate::ports::ToolContext {
        use crate::config::{Config, SecurityConfig, SecurityMode};
        use crate::domain::TunnelManager;
        use crate::domain::{CommandHistory, ExecuteCommandUseCase};
        use crate::ports::ExecutorRouter;
        use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
        use crate::ssh::SessionManager;
        use std::sync::Arc;
        let security = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: Vec::new(),
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts: server1_hosts(),
            security: security.clone(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&security));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(
            &crate::domain::history::HistoryConfig::default(),
        ));
        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));
        crate::ports::ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::mock(output)),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(crate::config::SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            pending_requests: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshLatencyTestHandler::new();
        let ctx = pipeline_ctx(mock_output(
            "PING 8.8.8.8: 64 bytes, seq=0 ttl=118 time=12.345 ms\nround-trip min/avg/max = 10.1/12.3/15.2 ms",
        ));
        let result = handler
            .execute(Some(json!({"host": "server1", "target": "8.8.8.8"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        assert!(!result.content.is_empty());
    }
}
