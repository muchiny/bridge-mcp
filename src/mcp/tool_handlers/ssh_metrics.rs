//! SSH Metrics Tool Handler
//!
//! Collects system metrics from a remote host and returns structured JSON.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::domain::data_reduction::DataReductionArgs;
use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::parse_metrics::{self, SECTION_SEPARATOR, SystemMetrics};
use crate::error::{BridgeError, Result};
use crate::mcp::apps::dashboard;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp::standard_tool::apply_reduction;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::{is_retryable_error, with_retry_if};

/// Metric types that can be collected
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum MetricType {
    Cpu,
    Memory,
    Disk,
    Network,
    Load,
}

/// Arguments for `ssh_metrics` tool
#[derive(Debug, Deserialize)]
struct SshMetricsArgs {
    host: String,
    metrics: Vec<MetricType>,
    timeout_seconds: Option<u64>,
}

/// SSH Metrics tool handler
#[mcp_tool(name = "ssh_metrics", group = "monitoring", annotation = "read_only")]
pub struct SshMetricsHandler;

impl SshMetricsHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "metrics": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["cpu", "memory", "disk", "network", "load"]
                },
                "description": "One or more metric types to collect: cpu (usage + cores), memory (total/used/free bytes), disk (filesystem usage via df), network (interface rx/tx bytes), load (1/5/15 min averages + uptime)",
                "minItems": 1
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["host", "metrics"]
    }"#;

    /// Build the compound command that collects all requested metrics.
    /// Each metric section is separated by `SECTION_SEPARATOR`.
    fn build_command(metrics: &[MetricType]) -> String {
        let mut parts = Vec::new();

        for metric in metrics {
            let cmd = match metric {
                MetricType::Cpu => "head -1 /proc/stat; nproc",
                MetricType::Memory => "free -b",
                MetricType::Disk => "df -B1",
                MetricType::Network => "cat /proc/net/dev",
                MetricType::Load => "cat /proc/loadavg; cat /proc/uptime",
            };
            parts.push(cmd.to_string());
        }

        parts.join(&format!("; echo '{SECTION_SEPARATOR}'; "))
    }
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl ToolHandler for SshMetricsHandler {
    fn name(&self) -> &'static str {
        "ssh_metrics"
    }

    fn description(&self) -> &'static str {
        "Collect system metrics from a single Linux host as structured, parseable JSON \
         (reads /proc/stat, /proc/net/dev, free, df, /proc/loadavg). Supports jq_filter \
         for server-side reduction. Available metric types: cpu, memory, disk, network, load \
         — pass any combination in the metrics array. For metrics from multiple hosts in \
         parallel, use ssh_metrics_multi instead. For Windows hosts use ssh_win_perf_cpu, \
         ssh_win_perf_memory, ssh_win_perf_disk, or ssh_win_perf_overview instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    fn output_kind(&self) -> OutputKind {
        OutputKind::Json
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(mut v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let dr = DataReductionArgs::extract(&mut v);
        let args: SshMetricsArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        if args.metrics.is_empty() {
            return Err(BridgeError::McpInvalidRequest(
                "metrics array must not be empty".to_string(),
            ));
        }

        // Get host config
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        let command = Self::build_command(&args.metrics);

        // Validate command
        if let Err(e) = ctx.execute_use_case.validate_builtin(&command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case
                .log_denied(&args.host, &command, &reason);
            return Err(e);
        }

        // Check rate limit
        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        info!(
            host = %args.host,
            metrics = ?args.metrics,
            "Collecting system metrics"
        );

        // Build limits with optional timeout override
        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds {
            limits.command_timeout_seconds = timeout;
        }

        let retry_config = limits.retry_config();

        // Resolve jump host
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        // Execute with retry
        let output = with_retry_if(
            &retry_config,
            "ssh_metrics",
            async || {
                let mut conn = ctx
                    .connection_pool
                    .get_connection_with_jump(&args.host, host_config, &limits, jump_host)
                    .await?;

                match conn.exec(&command, &limits).await {
                    Ok(output) => Ok(output),
                    Err(e) => {
                        conn.mark_failed();
                        Err(e)
                    }
                }
            },
            is_retryable_error,
        )
        .await;

        let output = output.inspect_err(|e| {
            ctx.execute_use_case
                .log_failure(&args.host, &command, &e.to_string());
        })?;

        let system_metrics = parse_sections(&output.stdout, &args.host, &args.metrics);

        // Log in history
        let _ = ctx
            .execute_use_case
            .process_success(&args.host, &command, &output.into());

        // Serialize to JSON and sanitize output
        let json_output = serde_json::to_string(&system_metrics)
            .unwrap_or_else(|e| format!("Error serializing metrics: {e}"));
        let mut json_output = ctx.sanitizer.sanitize(&json_output).into_owned();

        // Apply server-side data reduction (jq_filter / output_format=tsv / limit)
        apply_reduction(&mut json_output, &dr, OutputKind::Json)?;

        // Build dashboard app from metrics
        let mut dash = dashboard("System Metrics");
        if let Some(cpu) = &system_metrics.cpu {
            let usage = 100.0 - cpu.idle_percent;
            dash = dash.metric("CPU Usage", format!("{usage:.1}% ({} cores)", cpu.cores));
        }
        if let Some(mem) = &system_metrics.memory {
            #[allow(clippy::cast_precision_loss)]
            let used_gb = mem.used_bytes as f64 / 1_073_741_824.0;
            #[allow(clippy::cast_precision_loss)]
            let total_gb = mem.total_bytes as f64 / 1_073_741_824.0;
            dash = dash.metric(
                "Memory",
                format!(
                    "{used_gb:.1} / {total_gb:.1} GB ({:.1}%)",
                    mem.usage_percent
                ),
            );
        }
        if let Some(load) = &system_metrics.load {
            dash = dash.metric(
                "Load Average",
                format!(
                    "{:.2}, {:.2}, {:.2}",
                    load.load_1min, load.load_5min, load.load_15min
                ),
            );
        }
        dash = dash.refresh_action("ssh_metrics", serde_json::json!({"host": args.host}));
        let app = dash.build();

        let result = ToolCallResult::text(json_output).with_app(app);
        Ok(result)
    }
}

/// Parse the raw compound output into structured `SystemMetrics`.
fn parse_sections(stdout: &str, host: &str, metrics: &[MetricType]) -> SystemMetrics {
    let sections: Vec<&str> = stdout.split(SECTION_SEPARATOR).collect();

    let mut sm = SystemMetrics {
        host: host.to_string(),
        cpu: None,
        memory: None,
        disk: None,
        network: None,
        load: None,
    };

    for (i, metric_type) in metrics.iter().enumerate() {
        let section = sections.get(i).unwrap_or(&"").trim();
        match metric_type {
            MetricType::Cpu => sm.cpu = parse_metrics::parse_cpu(section),
            MetricType::Memory => sm.memory = parse_metrics::parse_memory(section),
            MetricType::Disk => sm.disk = parse_metrics::parse_disk(section),
            MetricType::Network => sm.network = parse_metrics::parse_network(section),
            MetricType::Load => sm.load = parse_metrics::parse_load(section),
        }
    }

    sm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[test]
    fn test_schema() {
        let handler = SshMetricsHandler;
        assert_eq!(handler.name(), "ssh_metrics");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("metrics")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshMetricsHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshMetricsHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "unknown_host",
                    "metrics": ["cpu"]
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown_host");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_builtin_tool_not_denied_in_standard_mode() {
        let handler = SshMetricsHandler;
        let ctx = create_test_context_with_host();

        // In standard mode (default), builtin tools bypass whitelist validation.
        // The command will pass validation but fail at SSH connection (expected).
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "metrics": ["cpu"]
                })),
                &ctx,
            )
            .await;

        // Should NOT be CommandDenied - the builtin tool passes validation
        assert!(result.is_err());
        if let BridgeError::CommandDenied { .. } = result.unwrap_err() {
            panic!("Builtin tool should not be denied in standard mode");
        }
        // Otherwise: SSH connection error is expected in test environment
    }

    #[test]
    fn test_build_command_single_metric() {
        let cmd = SshMetricsHandler::build_command(&[MetricType::Cpu]);
        assert_eq!(cmd, "head -1 /proc/stat; nproc");
    }

    #[test]
    fn test_build_command_multiple_metrics() {
        let cmd = SshMetricsHandler::build_command(&[MetricType::Cpu, MetricType::Memory]);
        assert!(cmd.contains("head -1 /proc/stat; nproc"));
        assert!(cmd.contains(SECTION_SEPARATOR));
        assert!(cmd.contains("free -b"));
    }

    #[test]
    fn test_build_command_all_metrics() {
        let cmd = SshMetricsHandler::build_command(&[
            MetricType::Cpu,
            MetricType::Memory,
            MetricType::Disk,
            MetricType::Network,
            MetricType::Load,
        ]);
        assert!(cmd.contains("head -1 /proc/stat"));
        assert!(cmd.contains("free -b"));
        assert!(cmd.contains("df -B1"));
        assert!(cmd.contains("cat /proc/net/dev"));
        assert!(cmd.contains("cat /proc/loadavg"));
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
        let handler = SshMetricsHandler;
        // Simulate cpu metric output: first line of /proc/stat + nproc
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output("cpu  12345 678 9012 345678 901 0 234 0 0 0\n4\n"),
        );
        let result = handler
            .execute(Some(json!({"host": "server1", "metrics": ["cpu"]})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
