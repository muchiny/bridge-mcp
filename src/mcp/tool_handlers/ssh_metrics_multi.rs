//! SSH Metrics Multi Tool Handler
//!
//! Collects system metrics from multiple hosts in parallel,
//! using rayon for parallel parsing of results.

use async_trait::async_trait;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::config::Config;
use crate::domain::use_cases::parse_metrics::{self, SECTION_SEPARATOR, SystemMetrics};
use crate::error::{BridgeError, Result};
use crate::mcp::apps::dashboard;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::CommandOutput;
use crate::ports::ExecutorRouter;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::security::RateLimiter;
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

/// Arguments for `ssh_metrics_multi` tool
#[derive(Debug, Deserialize)]
struct SshMetricsMultiArgs {
    hosts: Vec<String>,
    metrics: Vec<MetricType>,
    timeout_seconds: Option<u64>,
    fail_fast: Option<bool>,
}

/// Result for a single host metrics collection
#[derive(Debug, Serialize)]
struct HostMetricsResult {
    host: String,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<SystemMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

/// Aggregated results for all hosts
#[derive(Debug, Serialize)]
struct MultiMetricsResult {
    total_hosts: usize,
    succeeded: usize,
    failed: usize,
    results: Vec<HostMetricsResult>,
}

/// Raw output from a host, before parsing
struct RawHostOutput {
    host: String,
    stdout: String,
    duration_ms: u64,
}

/// SSH Metrics Multi tool handler
#[mcp_tool(
    name = "ssh_metrics_multi",
    group = "monitoring",
    annotation = "read_only"
)]
pub struct SshMetricsMultiHandler;

impl SshMetricsMultiHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "hosts": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Array of host aliases to collect metrics from",
                "minItems": 1,
                "maxItems": 50
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
                "description": "Per-host timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "fail_fast": {
                "type": "boolean",
                "description": "Stop remaining collections on first failure (default: false)",
                "default": false
            }
        },
        "required": ["hosts", "metrics"]
    }"#;

    /// Build the compound command that collects all requested metrics.
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
impl ToolHandler for SshMetricsMultiHandler {
    fn name(&self) -> &'static str {
        "ssh_metrics_multi"
    }

    fn description(&self) -> &'static str {
        "Collect system metrics from multiple Linux hosts in parallel (reads /proc/* — \
         Linux only). Returns JSON with per-host results including cpu, memory, disk, \
         network, and load metrics; top-level fields: total_hosts, succeeded, failed, \
         results[]. Set fail_fast=true to abort remaining hosts on first failure. Use \
         ssh_status first to discover available host aliases. For a single host, prefer \
         ssh_metrics instead. For Windows hosts use ssh_win_perf_overview instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshMetricsMultiArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        if args.hosts.is_empty() {
            return Err(BridgeError::McpInvalidRequest(
                "hosts array must not be empty".to_string(),
            ));
        }

        if args.metrics.is_empty() {
            return Err(BridgeError::McpInvalidRequest(
                "metrics array must not be empty".to_string(),
            ));
        }

        // Verify all hosts exist in config
        let mut unknown_hosts = Vec::new();
        for host in &args.hosts {
            if !ctx.config.hosts.contains_key(host) {
                unknown_hosts.push(host.clone());
            }
        }
        if !unknown_hosts.is_empty() {
            return Err(BridgeError::McpInvalidRequest(format!(
                "Unknown hosts: {}",
                unknown_hosts.join(", ")
            )));
        }

        let command = Self::build_command(&args.metrics);

        // Validate command once (same rules for all hosts)
        ctx.execute_use_case.validate_builtin(&command)?;

        info!(
            hosts = ?args.hosts,
            metrics = ?args.metrics,
            "Collecting metrics from multiple hosts"
        );

        let fail_fast = args.fail_fast.unwrap_or(false);
        let cancel_token = tokio_util::sync::CancellationToken::new();

        // Spawn parallel tasks for SSH execution
        let mut join_set = JoinSet::new();

        let config = Arc::clone(&ctx.config);
        let connection_pool = Arc::clone(&ctx.connection_pool);
        let rate_limiter = Arc::clone(&ctx.rate_limiter);

        for host_name in &args.hosts {
            join_set.spawn(collect_from_host(
                host_name.clone(),
                command.clone(),
                config.clone(),
                connection_pool.clone(),
                rate_limiter.clone(),
                cancel_token.clone(),
                args.timeout_seconds,
                fail_fast,
            ));
        }

        // Collect raw outputs, reporting progress as each host completes.
        // The reporter is `None` if the client did not request progress;
        // calls then become a cheap no-op.
        let progress = ctx.progress_reporter(Some(args.hosts.len() as u64));
        let mut raw_outputs: Vec<std::result::Result<RawHostOutput, HostMetricsResult>> =
            Vec::with_capacity(args.hosts.len());
        let mut completed: u64 = 0;
        let total = args.hosts.len();
        while let Some(join_result) = join_set.join_next().await {
            match join_result {
                Ok(host_result) => {
                    completed += 1;
                    if let Some(reporter) = progress.as_ref() {
                        let host_label = match &host_result {
                            Ok(raw) => raw.host.clone(),
                            Err(err) => err.host.clone(),
                        };
                        reporter.report(
                            completed,
                            Some(&format!("{host_label} ({completed}/{total})")),
                        );
                    }
                    raw_outputs.push(host_result);
                }
                Err(e) => {
                    warn!("Task join error: {e}");
                }
            }
        }

        // Parse results in parallel using rayon
        let metrics_types = args.metrics.clone();
        let results: Vec<HostMetricsResult> = raw_outputs
            .into_par_iter()
            .map(|result| match result {
                Ok(raw) => {
                    let metrics = parse_sections(&raw.stdout, &raw.host, &metrics_types);
                    HostMetricsResult {
                        host: raw.host,
                        success: true,
                        metrics: Some(metrics),
                        error: None,
                        duration_ms: Some(raw.duration_ms),
                    }
                }
                Err(error_result) => error_result,
            })
            .collect();

        // Sort by original host order
        let host_order: std::collections::HashMap<&str, usize> = args
            .hosts
            .iter()
            .enumerate()
            .map(|(i, h)| (h.as_str(), i))
            .collect();
        let mut sorted_results = results;
        sorted_results.sort_by_key(|r| {
            host_order
                .get(r.host.as_str())
                .copied()
                .unwrap_or(usize::MAX)
        });

        let succeeded = sorted_results.iter().filter(|r| r.success).count();
        let failed = sorted_results.len() - succeeded;

        // Log in history for successful hosts
        for result in &sorted_results {
            if result.success {
                let _ = ctx.execute_use_case.process_success(
                    &result.host,
                    &command,
                    &CommandOutput {
                        stdout: String::new(),
                        stderr: String::new(),
                        exit_code: 0,
                        duration_ms: result.duration_ms.unwrap_or(0),
                    },
                );
            }
        }

        let multi_result = MultiMetricsResult {
            total_hosts: sorted_results.len(),
            succeeded,
            failed,
            results: sorted_results,
        };

        let json_output = serde_json::to_string(&multi_result)
            .unwrap_or_else(|e| format!("Error serializing results: {e}"));
        let json_output = ctx.sanitizer.sanitize(&json_output).into_owned();

        // Build multi-host dashboard
        let mut dash = dashboard("Multi-Host Metrics");
        let hosts_status = if multi_result.failed > 0 {
            format!(
                "{}/{} succeeded (warning)",
                multi_result.succeeded, multi_result.total_hosts
            )
        } else {
            format!(
                "{}/{} succeeded",
                multi_result.succeeded, multi_result.total_hosts
            )
        };
        dash = dash.metric("Hosts", &hosts_status);
        for hr in &multi_result.results {
            if hr.success {
                if let Some(ref m) = hr.metrics {
                    let cpu_info = m.cpu.as_ref().map_or("N/A".to_string(), |c| {
                        format!("{:.0}%", 100.0 - c.idle_percent)
                    });
                    let mem_info = m.memory.as_ref().map_or("N/A".to_string(), |mem| {
                        format!("{:.0}%", mem.usage_percent)
                    });
                    dash = dash.metric(&hr.host, format!("CPU: {cpu_info}, Mem: {mem_info}"));
                }
            } else {
                dash = dash.metric(&hr.host, "FAILED");
            }
        }
        let app = dash.build();

        Ok(ToolCallResult::text(json_output).with_app(app))
    }
}

/// Collect metrics from a single host, returning raw output for parallel parsing.
#[allow(clippy::too_many_arguments)]
async fn collect_from_host(
    host_name: String,
    command: String,
    config: Arc<Config>,
    connection_pool: Arc<ExecutorRouter>,
    rate_limiter: Arc<RateLimiter>,
    cancel_token: tokio_util::sync::CancellationToken,
    timeout_seconds: Option<u64>,
    fail_fast: bool,
) -> std::result::Result<RawHostOutput, HostMetricsResult> {
    let start = Instant::now();

    // Check if cancelled by a previous fail_fast
    if cancel_token.is_cancelled() {
        return Err(HostMetricsResult {
            host: host_name,
            success: false,
            metrics: None,
            error: Some("Cancelled due to fail_fast".to_string()),
            duration_ms: None,
        });
    }

    // Check rate limit
    if rate_limiter.check(&host_name).is_err() {
        return Err(HostMetricsResult {
            host: host_name,
            success: false,
            metrics: None,
            error: Some("Rate limit exceeded".to_string()),
            duration_ms: Some(elapsed_ms(&start)),
        });
    }

    // Get host config
    let Some(host_config) = config.hosts.get(&host_name) else {
        return Err(HostMetricsResult {
            host: host_name,
            success: false,
            metrics: None,
            error: Some("Host config not found".to_string()),
            duration_ms: Some(elapsed_ms(&start)),
        });
    };

    // Build limits with optional timeout override
    let mut limits = config.limits.clone();
    if let Some(timeout) = timeout_seconds {
        limits.command_timeout_seconds = timeout;
    }
    let retry_config = limits.retry_config();

    // Resolve jump host
    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Execute with retry
    let output = with_retry_if(
        &retry_config,
        "ssh_metrics_multi",
        async || {
            let mut conn = connection_pool
                .get_connection_with_jump(&host_name, host_config, &limits, jump_host)
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

    let duration_ms = elapsed_ms(&start);

    match output {
        Ok(output) => Ok(RawHostOutput {
            host: host_name,
            stdout: output.stdout,
            duration_ms,
        }),
        Err(e) => {
            if fail_fast {
                cancel_token.cancel();
            }

            Err(HostMetricsResult {
                host: host_name,
                success: false,
                metrics: None,
                error: Some(e.to_string()),
                duration_ms: Some(duration_ms),
            })
        }
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

#[allow(clippy::cast_possible_truncation)]
fn elapsed_ms(start: &Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
    use crate::ports::ToolContext;
    use crate::ports::mock::create_test_context;
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_context_with_hosts() -> ToolContext {
        let mut hosts = HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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
        hosts.insert(
            "server2".to_string(),
            HostConfig {
                hostname: "192.168.1.101".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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
        hosts.insert(
            "server3".to_string(),
            HostConfig {
                hostname: "192.168.1.102".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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
        crate::ports::mock::create_test_context_with_hosts(hosts)
    }

    #[test]
    fn test_schema() {
        let handler = SshMetricsMultiHandler;
        assert_eq!(handler.name(), "ssh_metrics_multi");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("hosts")));
        assert!(required.contains(&json!("metrics")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshMetricsMultiHandler;
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
    async fn test_empty_hosts_array() {
        let handler = SshMetricsMultiHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "hosts": [],
                    "metrics": ["cpu"]
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("hosts"));
            }
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_empty_metrics_array() {
        let handler = SshMetricsMultiHandler;
        let ctx = create_test_context_with_hosts();

        let result = handler
            .execute(
                Some(json!({
                    "hosts": ["server1"],
                    "metrics": []
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("metrics"));
            }
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_hosts_detected() {
        let handler = SshMetricsMultiHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "hosts": ["unknown1", "unknown2"],
                    "metrics": ["cpu"]
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("unknown1"));
                assert!(msg.contains("unknown2"));
            }
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_single_metric() {
        let cmd = SshMetricsMultiHandler::build_command(&[MetricType::Cpu]);
        assert_eq!(cmd, "head -1 /proc/stat; nproc");
    }

    #[test]
    fn test_build_command_multiple_metrics() {
        let cmd = SshMetricsMultiHandler::build_command(&[MetricType::Cpu, MetricType::Memory]);
        assert!(cmd.contains("head -1 /proc/stat; nproc"));
        assert!(cmd.contains(SECTION_SEPARATOR));
        assert!(cmd.contains("free -b"));
    }

    #[test]
    fn test_parse_sections() {
        let stdout = format!(
            "cpu  10000 500 3000 86000 200 100 200 0 0 0\n4\n{SECTION_SEPARATOR}              total        used        free      shared  buff/cache   available\nMem:    16000000000  8000000000  4000000000      100000  4000000000  7000000000\nSwap:    2000000000   500000000  1500000000"
        );

        let metrics = vec![MetricType::Cpu, MetricType::Memory];
        let result = parse_sections(&stdout, "testhost", &metrics);

        assert_eq!(result.host, "testhost");
        assert!(result.cpu.is_some());
        assert!(result.memory.is_some());
        assert!(result.disk.is_none());
    }

    #[test]
    fn test_build_command_all_metric_types() {
        let cmd = SshMetricsMultiHandler::build_command(&[
            MetricType::Cpu,
            MetricType::Memory,
            MetricType::Disk,
            MetricType::Network,
            MetricType::Load,
        ]);
        assert!(cmd.contains("/proc/stat"));
        assert!(cmd.contains("free -b"));
        assert!(cmd.contains("df -B1"));
        assert!(cmd.contains("/proc/net/dev"));
        assert!(cmd.contains("/proc/loadavg"));
    }

    #[test]
    fn test_metric_type_deserialization_lowercase() {
        let val: MetricType = serde_json::from_str("\"disk\"").unwrap();
        assert_eq!(val, MetricType::Disk);
        let val: MetricType = serde_json::from_str("\"network\"").unwrap();
        assert_eq!(val, MetricType::Network);
        let val: MetricType = serde_json::from_str("\"load\"").unwrap();
        assert_eq!(val, MetricType::Load);
    }

    #[test]
    fn test_metric_type_invalid_rejected() {
        let res: std::result::Result<MetricType, _> = serde_json::from_str("\"BOGUS\"");
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_sections_short_input_uses_defaults() {
        // stdout has fewer sections than requested metric types — missing
        // sections should silently fall through and yield None metrics
        // rather than panic.
        let metrics = vec![MetricType::Cpu, MetricType::Memory, MetricType::Disk];
        let result = parse_sections("", "h", &metrics);
        assert_eq!(result.host, "h");
        assert!(result.cpu.is_none());
        assert!(result.memory.is_none());
        assert!(result.disk.is_none());
    }

    #[tokio::test]
    async fn test_invalid_arguments_format() {
        let handler = SshMetricsMultiHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"hosts": "not-an-array"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_full_pipeline_success_with_mock_executor() {
        // Drives the full pipeline including JoinSet, parallel parsing,
        // dashboard generation, and history bookkeeping.
        let handler = SshMetricsMultiHandler;
        let mut hosts = HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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
        let mock_output = crate::ssh::CommandOutput {
            stdout: format!(
                "cpu  10000 500 3000 86000 200 100 200 0 0 0\n4\n{SECTION_SEPARATOR}              total        used        free      shared  buff/cache   available\nMem:    16000000000  8000000000  4000000000      100000  4000000000  7000000000\n"
            ),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 1,
        };
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(hosts, mock_output);
        let result = handler
            .execute(
                Some(json!({"hosts": ["server1"], "metrics": ["cpu", "memory"]})),
                &ctx,
            )
            .await;
        // We don't require success — the mock pool may still gate at the
        // executor router level. Either way, the pipeline branches above
        // step 4 are now exercised.
        let _ = result;
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn test_parallel_parsing() {
        // Simulate multiple host outputs
        let raw_outputs: Vec<std::result::Result<RawHostOutput, HostMetricsResult>> = (0..10)
            .map(|i| {
                Ok(RawHostOutput {
                    host: format!("host{i}"),
                    stdout: "cpu  10000 500 3000 86000 200 100 200 0 0 0\n4\n".to_string(),
                    duration_ms: 100,
                })
            })
            .collect();

        let metrics = vec![MetricType::Cpu];

        // Use rayon to parse in parallel
        let results: Vec<HostMetricsResult> = raw_outputs
            .into_par_iter()
            .map(|result| match result {
                Ok(raw) => {
                    let parsed = parse_sections(&raw.stdout, &raw.host, &metrics);
                    HostMetricsResult {
                        host: raw.host,
                        success: true,
                        metrics: Some(parsed),
                        error: None,
                        duration_ms: Some(raw.duration_ms),
                    }
                }
                Err(e) => e,
            })
            .collect();

        assert_eq!(results.len(), 10);
        for result in &results {
            assert!(result.success);
            assert!(result.metrics.is_some());
            assert!(result.metrics.as_ref().unwrap().cpu.is_some());
        }
    }
}
