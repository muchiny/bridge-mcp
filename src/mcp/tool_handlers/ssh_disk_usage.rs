//! Handler for the `ssh_disk_usage` tool.
//!
//! Shows disk usage and filesystem space on a remote host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::domain::output_truncator::truncate_output_with_cache;
use crate::error::{BridgeError, Result};
use crate::mcp::apps::table;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::{is_retryable_error, with_retry_if};

use super::utils::shell_escape;

/// Arguments for the `ssh_disk_usage` tool.
#[derive(Debug, Deserialize)]
struct SshDiskUsageArgs {
    /// Target host name from configuration.
    host: String,
    /// Optional path to check disk usage for.
    path: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

/// Handler that shows disk usage and filesystem space on a remote host.
#[mcp_tool(
    name = "ssh_disk_usage",
    group = "monitoring",
    annotation = "read_only"
)]
pub struct SshDiskUsageHandler;

#[async_trait]
impl ToolHandler for SshDiskUsageHandler {
    fn name(&self) -> &'static str {
        "ssh_disk_usage"
    }

    fn description(&self) -> &'static str {
        "Show disk usage and filesystem space on a remote host. Prefer this over ssh_exec \
         for disk checks. Without a path, shows all mounted filesystems (df -h). With a path, \
         shows both the directory size (du -sh) AND the filesystem it resides on (df -h) — \
         use this when you need per-directory sizes in addition to filesystem usage. \
         Prefer ssh_disk_usage over ssh_storage_df when you also need directory size (du -sh) \
         for a specific path; ssh_storage_df only shows filesystem-level df output. \
         Returns human-readable text output. For structured JSON disk metrics as part of a \
         broader system health check, use ssh_metrics with metrics=['disk'] instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_disk_usage",
            description: "Show disk usage and filesystem space on a remote host. Prefer this over ssh_exec for disk checks. Without a path, shows all mounted filesystems (df -h). With a path, shows both the directory size (du -sh) AND the filesystem it resides on (df -h) — use this when you need per-directory sizes. Prefer ssh_disk_usage over ssh_storage_df when you also need directory size (du -sh) for a specific path; ssh_storage_df only shows filesystem-level df output. Returns human-readable text output. For structured JSON disk metrics as part of a broader system health check, use ssh_metrics with metrics=['disk'] instead.",
            input_schema: r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "path": {
                        "type": "string",
                        "description": "Optional absolute path: shows directory size (du -sh) AND the filesystem it resides on (df -h). Must be an absolute path (e.g. /var/log)."
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host"]
            }"#,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshDiskUsageArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        let command = if let Some(ref path) = args.path {
            let escaped_path = shell_escape(path);
            format!("du -sh {escaped_path} && df -h {escaped_path}")
        } else {
            "df -h".to_string()
        };

        if let Err(e) = ctx.execute_use_case.validate_builtin(&command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case
                .log_denied(&args.host, &command, &reason);
            return Err(e);
        }

        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        info!(host = %args.host, "Checking disk usage");

        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds {
            limits.command_timeout_seconds = timeout;
        }
        let retry_config = limits.retry_config();
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        let output = with_retry_if(
            &retry_config,
            "ssh_disk_usage",
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

        let response = ctx
            .execute_use_case
            .process_success(&args.host, &command, &output.into());

        if response.exit_code != 0 {
            warn!(host = %args.host, exit_code = response.exit_code, "ssh_disk_usage failed");
        }

        #[allow(clippy::cast_possible_truncation)]
        let max_chars = args
            .max_output
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);
        let truncated_stdout =
            truncate_output_with_cache(&response.stdout, max_chars, ctx.output_cache.as_deref())
                .await;

        let mut output_text = response.format_for_llm(&truncated_stdout);
        if let Some(ref save_path) = args.save_output {
            match crate::mcp::tool_handlers::utils::save_output_to_file(save_path, &response.output)
                .await
            {
                Ok(msg) => output_text = format!("{output_text}\n{msg}"),
                Err(msg) => {
                    output_text = format!("{output_text}\nsave_output error: {msg}");
                }
            }
        }

        let result = ToolCallResult::text(output_text);
        Ok(post_process_disk_usage(result, &args, &response.stdout))
    }
}

/// Post-process disk usage output into a table component.
fn post_process_disk_usage(
    result: ToolCallResult,
    args: &SshDiskUsageArgs,
    output: &str,
) -> ToolCallResult {
    let Some(parsed) = super::utils::parse_columnar_output(output) else {
        return result;
    };
    let mut tbl = table("Disk Usage");
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
        "ssh_disk_usage",
        Some(json!({"host": args.host})),
    );
    ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDiskUsageHandler;
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
        let handler = SshDiskUsageHandler;
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
        let handler = SshDiskUsageHandler;
        assert_eq!(handler.name(), "ssh_disk_usage");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_disk_usage");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/var/log",
            "timeout_seconds": 60,
            "max_output": 5000,
            "save_output": "/tmp/disk.txt"
        });
        let args: SshDiskUsageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path.as_deref(), Some("/var/log"));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/disk.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshDiskUsageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.path.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDiskUsageHandler;
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("path"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshDiskUsageArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDiskUsageArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDiskUsageHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
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
        let handler = SshDiskUsageHandler;
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       41284928 6173696  33000440  16% /\n",
            ),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
