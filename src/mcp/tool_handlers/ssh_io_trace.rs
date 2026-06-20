//! Handler for the `ssh_io_trace` tool.
//!
//! Traces disk I/O activity on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::performance::PerformanceCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_io_trace` tool.
#[derive(Debug, Deserialize)]
pub struct SshIoTraceArgs {
    host: String,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    duration: Option<u64>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshIoTraceArgs);

#[mcp_standard_tool(name = "ssh_io_trace", group = "performance", annotation = "read_only")]
pub struct IoTraceTool;

impl StandardTool for IoTraceTool {
    type Args = SshIoTraceArgs;

    const NAME: &'static str = "ssh_io_trace";

    const DESCRIPTION: &'static str = "Trace disk I/O throughput, IOPS, and latency on a Linux \
        host using iostat (falls back to /proc/diskstats). Optionally filter by device name \
        (e.g. sda, nvme0n1). Duration is capped at 60 seconds. For CPU/syscall profiling use \
        ssh_perf_trace; for network latency use ssh_latency_test; for quick write-speed \
        benchmarks use ssh_benchmark. For Windows disk counters use ssh_win_perf_disk instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "device": {
                "type": "string",
                "description": "Device name to monitor (e.g. sda, nvme0n1). Omit for all devices"
            },
            "duration": {
                "type": "integer",
                "description": "Monitoring duration in seconds (default: 5, max: 60)",
                "minimum": 1,
                "maximum": 60
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

    fn build_command(args: &SshIoTraceArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PerformanceCommandBuilder::build_io_trace_command(
            args.device.as_deref(),
            args.duration.unwrap_or(5),
        ))
    }

    fn validate(args: &SshIoTraceArgs, _host_config: &HostConfig) -> Result<()> {
        PerformanceCommandBuilder::validate_duration(args.duration.unwrap_or(5))?;
        Ok(())
    }
}

/// Handler for the `ssh_io_trace` tool.
pub type SshIoTraceHandler = StandardToolHandler<IoTraceTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshIoTraceHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshIoTraceHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshIoTraceHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_io_trace");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "myhost", "device": "sda", "duration": 10});
        let args: SshIoTraceArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.device.as_deref(), Some("sda"));
        assert_eq!(args.duration, Some(10));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshIoTraceArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.device.is_none());
        assert!(args.duration.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshIoTraceHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("device"));
        assert!(props.contains_key("duration"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h"});
        let args: SshIoTraceArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshIoTraceArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshIoTraceArgs>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "server1",
            "device": "nvme0n1",
            "duration": 30,
            "timeout_seconds": 120,
            "max_output": 10000,
            "save_output": "/tmp/io.txt"
        });
        let args: SshIoTraceArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.device.as_deref(), Some("nvme0n1"));
        assert_eq!(args.duration, Some(30));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output, Some("/tmp/io.txt".to_string()));
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
        let args: SshIoTraceArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = IoTraceTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_build_command_with_device() {
        let args: SshIoTraceArgs =
            serde_json::from_value(json!({"host": "s", "device": "sda", "duration": 10})).unwrap();
        let host = test_host_config();
        let cmd = IoTraceTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshIoTraceArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "Device\ttps\tkB_read/s\tkB_wrtn/s\nsda\t10\t100\t50\n";
        let result = IoTraceTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshIoTraceArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = IoTraceTool::post_process(result, &args, "", &dr);
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
        let handler = SshIoTraceHandler::new();
        let ctx = pipeline_ctx(mock_output(
            "Total (TPS) Read (KB/s) Write (KB/s)\nsda 50.00 2048.00 1024.00",
        ));
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        assert!(!result.content.is_empty());
    }
}
