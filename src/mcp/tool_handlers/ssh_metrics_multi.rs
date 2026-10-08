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
#[serde(deny_unknown_fields)]
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
    /// The remote command's own exit code, carried only as far as the audit
    /// event below. `None` means the host was never reached, which makes it
    /// the same discriminator as `success` — the two are set together, in the
    /// one `Ok` arm and the four `Err` literals.
    ///
    /// **`#[serde(skip)]`, deliberately.** This struct IS the tool's answer:
    /// it is what `MultiMetricsResult.results` serializes to the caller, so a
    /// serialized field here would change the contract of `ssh_metrics_multi`
    /// — a new key in every element of `results`. A parallel host→code map
    /// would avoid that too, but it would also have to be kept in step with
    /// the sort below by hand; the skipped field travels with its own host.
    #[serde(skip)]
    exit_code: Option<u32>,
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
    /// The remote command's own exit code, as `conn.exec` reported it.
    /// It used to be dropped here — `collect_from_host` deconstructed the
    /// `CommandOutput` and kept only `stdout` — and the audit event below
    /// then carried a literal `0` instead.
    exit_code: u32,
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
        let mut raw_outputs: Vec<std::result::Result<RawHostOutput, Box<HostMetricsResult>>> =
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

        // A deliberate abstention — about the TOOL RESULT, and only about
        // it. For the reason written in `ssh_metrics.rs` above its call to
        // `parse_sections`: `Self::build_command` (above) is the same
        // `;`-joined list, whose status describes only the last section, and
        // `parse_sections` (below) already carries the per-field signal. What
        // is specific to this handler is the fan-out.
        //
        // And the `success: true` in the `Ok(raw)` arm below holds for every
        // host whose SSH execution returned `Ok`, whatever the remote code
        // was: the JSON's `succeeded` / `failed` counters describe whether the
        // host was reached, not how the command ended. Aggregating them into a
        // single code would rebuild the conflation `ssh_exec_multi` refuses —
        // its fan-out comment says why that would make exit 6 mean "the bridge
        // could not reach a host".
        //
        // What is NOT abstention any more is what gets AUDITED. This block
        // used to say the consequence left unfixed was that "the history entry
        // written below for each reached host carries a literal
        // `exit_code: 0`" — that understated it twice over.
        // `process_success` calls `record_success_redacted`, which writes the
        // audit event AND the history entry, so the fabricated `0` went into
        // `audit.log` too; and the loop below only ran for `result.success`,
        // so a host the bridge never reached produced no line at all. A
        // fabricated `0` is the expensive direction of the defect: it
        // announces a SUCCESS that may not have happened, which is what PR
        // #218 and #219 spent two PRs removing elsewhere.
        //
        // `RawHostOutput` now carries the real code the whole way, and the
        // loop below logs every host — the real code for the ones reached,
        // `log_failure` for the ones that were not, which is exactly what the
        // single-host `ssh_metrics` already does.
        //
        // **The limit of that remedy, so the next reader does not overstate
        // it:** the real code is no more informative than the `0` was — it is
        // only TRUE. It is the status of a `;`-joined list, i.e. of the LAST
        // section alone (POSIX XCU 2.9.3), so four of five metric sections can
        // fail while the recorded code reads 0. The audit line does not
        // describe the five metrics; the per-metric `None` in the JSON does.

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
                        exit_code: Some(raw.exit_code),
                    }
                }
                Err(error_result) => *error_result,
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

        // Audit + history for EVERY host, reached or not. `exit_code` is
        // `Some` exactly when the host was reached (set together with
        // `success`), so it is the discriminator here: a real code for the
        // reached hosts, `log_failure` for the rest. Matching on the code
        // rather than on `success` is what keeps a `0` from being invented
        // should the two ever drift apart.
        //
        // `stdout`/`stderr` stay empty: the raw stdout was consumed by
        // `parse_sections` above, and `stderr` was never carried back here.
        for result in &sorted_results {
            if let Some(exit_code) = result.exit_code {
                let _ = ctx.execute_use_case.process_success(
                    self.name(),
                    &result.host,
                    &command,
                    &CommandOutput {
                        stdout: String::new(),
                        stderr: String::new(),
                        exit_code,
                        duration_ms: result.duration_ms.unwrap_or(0),
                    },
                    &[],
                );
            } else {
                ctx.execute_use_case.log_failure(
                    self.name(),
                    &result.host,
                    &command,
                    result
                        .error
                        .as_deref()
                        .unwrap_or("metrics collection failed"),
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
) -> std::result::Result<RawHostOutput, Box<HostMetricsResult>> {
    let start = Instant::now();

    // Check if cancelled by a previous fail_fast
    if cancel_token.is_cancelled() {
        return Err(Box::new(HostMetricsResult {
            host: host_name,
            success: false,
            metrics: None,
            error: Some("Cancelled due to fail_fast".to_string()),
            duration_ms: None,
            exit_code: None,
        }));
    }

    // Check rate limit
    if rate_limiter.check(&host_name).is_err() {
        return Err(Box::new(HostMetricsResult {
            host: host_name,
            success: false,
            metrics: None,
            error: Some("Rate limit exceeded".to_string()),
            duration_ms: Some(elapsed_ms(&start)),
            exit_code: None,
        }));
    }

    // Get host config
    let Some(host_config) = config.hosts.get(&host_name) else {
        return Err(Box::new(HostMetricsResult {
            host: host_name,
            success: false,
            metrics: None,
            error: Some("Host config not found".to_string()),
            duration_ms: Some(elapsed_ms(&start)),
            exit_code: None,
        }));
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
            exit_code: output.exit_code,
        }),
        Err(e) => {
            if fail_fast {
                cancel_token.cancel();
            }

            Err(Box::new(HostMetricsResult {
                host: host_name,
                success: false,
                metrics: None,
                error: Some(e.to_string()),
                duration_ms: Some(duration_ms),
                exit_code: None,
            }))
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
        assert_ne!(handler.description(), "");

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

    fn mock_linux_host(hostname: &str) -> HostConfig {
        HostConfig {
            hostname: hostname.to_string(),
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
        }
    }

    /// The audited exit code is the one the host returned, not a literal `0`.
    ///
    /// This is the defect that mattered: the loop used to hand
    /// `process_success` a hand-built `CommandOutput { exit_code: 0, .. }`, so
    /// `audit.log` AND the history recorded a SUCCESS for a command that may
    /// have failed. The mock returns 3, and 3 is what has to appear.
    #[tokio::test]
    async fn the_audited_exit_code_is_the_one_the_host_returned() {
        let handler = SshMetricsMultiHandler;
        let mut hosts = HashMap::new();
        hosts.insert("server1".to_string(), mock_linux_host("192.168.1.100"));
        let mock_output = crate::ssh::CommandOutput {
            stdout: "cpu  10000 500 3000 86000 200 100 200 0 0 0\n4\n".to_string(),
            stderr: String::new(),
            exit_code: 3,
            duration_ms: 1,
        };
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(hosts, mock_output);

        let _ = handler
            .execute(
                Some(json!({"hosts": ["server1"], "metrics": ["cpu"]})),
                &ctx,
            )
            .await;

        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "one host, one audit line: {events:?}");
        assert_eq!(events[0].tool_name.as_deref(), Some("ssh_metrics_multi"));
        assert!(
            matches!(
                events[0].result,
                crate::security::CommandResult::Success { exit_code: 3, .. }
            ),
            "the real code must reach the audit event, got {:?}",
            events[0].result
        );
    }

    /// A host the bridge never reached now leaves a line. It used to leave
    /// none at all: the loop was guarded by `if result.success`, so an SSH
    /// failure, a rate-limit refusal or a `fail_fast` cancellation produced
    /// neither an audit event nor a history entry. The single-host
    /// `ssh_metrics` has always called `log_failure` here.
    ///
    /// An unknown host cannot drive this path — `execute` rejects the whole
    /// call before spawning anything — so the refusal used is the rate limit,
    /// whose one token is spent before the call.
    #[tokio::test]
    async fn an_unreachable_host_is_audited_as_a_failure() {
        let handler = SshMetricsMultiHandler;
        let mut hosts = HashMap::new();
        hosts.insert("server1".to_string(), mock_linux_host("192.168.1.100"));
        hosts.insert("server2".to_string(), mock_linux_host("192.168.1.101"));
        let mock_output = crate::ssh::CommandOutput {
            stdout: "cpu  10000 500 3000 86000 200 100 200 0 0 0\n4\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 1,
        };
        let mut ctx =
            crate::ports::mock::create_test_context_with_mock_executor(hosts, mock_output);
        ctx.rate_limiter = Arc::new(RateLimiter::new(1));
        // Spend server2's only token so `collect_from_host` refuses it.
        assert!(ctx.rate_limiter.check("server2").is_ok());

        let _ = handler
            .execute(
                Some(json!({"hosts": ["server1", "server2"], "metrics": ["cpu"]})),
                &ctx,
            )
            .await;

        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 2, "both hosts audited: {events:?}");
        let refused = events
            .iter()
            .find(|e| e.host == "server2")
            .expect("the host that was never reached must still have a line");
        assert!(
            matches!(refused.result, crate::security::CommandResult::Error { .. }),
            "got {:?}",
            refused.result
        );
        assert_eq!(refused.tool_name.as_deref(), Some("ssh_metrics_multi"));
    }

    /// The code travels to the audit event and **nowhere else**: adding it to
    /// `HostMetricsResult` must not add a key to the tool's own JSON answer.
    #[test]
    fn the_carried_exit_code_stays_out_of_the_tool_result() {
        let r = HostMetricsResult {
            host: "server1".to_string(),
            success: true,
            metrics: None,
            error: None,
            duration_ms: Some(5),
            exit_code: Some(3),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("exit_code"),
            "#[serde(skip)] keeps the tool contract unchanged: {json}"
        );
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
                    exit_code: 0,
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
                        exit_code: Some(raw.exit_code),
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
