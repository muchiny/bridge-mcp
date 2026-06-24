//! Handler for the `ssh_find` tool.
//!
//! Finds files and directories on a remote host using the `find` command.

use std::fmt::Write;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::domain::output_truncator::truncate_output_with_cache;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::{is_retryable_error, with_retry_if};

use super::utils::shell_escape;

/// Arguments for the `ssh_find` tool.
#[derive(Debug, Deserialize)]
struct SshFindArgs {
    /// Target host name from configuration.
    host: String,
    /// The search root path.
    path: String,
    /// File name pattern (e.g., "*.log").
    name: Option<String>,
    /// File type filter: f (regular file), d (directory), l (symlink).
    #[serde(rename = "type")]
    file_type: Option<String>,
    /// Maximum directory depth (default: 5).
    max_depth: Option<u32>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

/// Handler that finds files and directories on a remote host.
#[mcp_tool(name = "ssh_find", group = "directory", annotation = "read_only")]
pub struct SshFindHandler;

/// Build the `find` command string from parsed arguments.
fn build_find_command(args: &SshFindArgs) -> String {
    let mut cmd = format!("find {}", shell_escape(&args.path));

    if let Some(depth) = args.max_depth {
        let _ = write!(cmd, " -maxdepth {depth}");
    } else {
        let _ = write!(cmd, " -maxdepth 5");
    }

    if let Some(ref name) = args.name {
        let _ = write!(cmd, " -name {}", shell_escape(name));
    }

    if let Some(ref ft) = args.file_type {
        let _ = write!(cmd, " -type {}", shell_escape(ft));
    }

    cmd.push_str(" 2>/dev/null");
    cmd
}

#[async_trait]
impl ToolHandler for SshFindHandler {
    fn name(&self) -> &'static str {
        "ssh_find"
    }

    fn description(&self) -> &'static str {
        "Find files and directories on a remote host. Prefer this over ssh_exec for file \
         searches as it provides safe escaping, path validation, and a default max depth of 5 \
         to prevent excessive traversal. Use name for glob patterns (e.g., '*.log') and type \
         for filtering (f=files, d=directories, l=symlinks). Only -name glob matching is \
         supported; for case-insensitive or regex searches use ssh_exec with find -iname/-regex. \
         Returns one file path per line (plain text); use limit=N to cap result count on large \
         filesystems or save_output=/tmp/out.txt to persist very large result sets. \
         For listing directory contents with metadata, use ssh_ls instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_find",
            description: "Find files and directories on a remote host. Prefer this over ssh_exec for file searches as it provides safe escaping, path validation, and a default max depth of 5 to prevent excessive traversal. Use name for glob patterns (e.g., '*.log') and type for filtering (f=files, d=directories, l=symlinks). Only -name glob matching is supported; for case-insensitive or regex searches use ssh_exec with find -iname/-regex. Returns one file path per line (plain text); use limit=N to cap result count on large filesystems or save_output=/tmp/out.txt to persist very large result sets. For listing directory contents with metadata, use ssh_ls instead.",
            input_schema: r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "path": {
                        "type": "string",
                        "description": "The search root path"
                    },
                    "name": {
                        "type": "string",
                        "description": "Glob pattern matched via find -name (e.g., '*.log'). Only -name glob matching is supported; case-insensitive (-iname) and regex (-regex/-iregex) patterns are not available — use ssh_exec for those."
                    },
                    "type": {
                        "type": "string",
                        "enum": ["f", "d", "l", "s", "p"],
                        "description": "File type filter: f (regular file), d (directory), l (symlink), s (socket), p (named pipe). Only -name glob matching is supported; for regex-based searches use ssh_exec with find -regex."
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum directory depth (default: 5)",
                        "minimum": 1,
                        "maximum": 20
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
                "required": ["host", "path"]
            }"#,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshFindArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Validate path is within declared workspace roots
        ctx.validate_root_scope(&args.path)?;

        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        let command = build_find_command(&args);

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

        info!(host = %args.host, path = %args.path, "Finding files");

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
            "ssh_find",
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
            warn!(host = %args.host, exit_code = response.exit_code, "ssh_find failed");
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

        Ok(ToolCallResult::text(output_text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFindHandler;
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
        let handler = SshFindHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/var/log"})),
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
        let handler = SshFindHandler;
        assert_eq!(handler.name(), "ssh_find");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_find");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/var/log",
            "name": "*.log",
            "type": "f",
            "max_depth": 3,
            "timeout_seconds": 60,
            "max_output": 5000,
            "save_output": "/tmp/find.txt"
        });
        let args: SshFindArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/var/log");
        assert_eq!(args.name.as_deref(), Some("*.log"));
        assert_eq!(args.file_type.as_deref(), Some("f"));
        assert_eq!(args.max_depth, Some(3));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/find.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/var/log"});
        let args: SshFindArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/var/log");
        assert!(args.name.is_none());
        assert!(args.file_type.is_none());
        assert!(args.max_depth.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFindHandler;
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("name"));
        assert!(props.contains_key("type"));
        assert!(props.contains_key("max_depth"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/var/log"});
        let args: SshFindArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFindArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFindHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "path": 456})), &ctx)
            .await;
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

    /// Creates a test context with permissive security (empty blacklist)
    /// because `ssh_find` appends `2>/dev/null` which is blocked by the
    /// default blacklist pattern `(?i)>\s*/dev/`.
    fn create_permissive_mock_ctx(
        hosts: std::collections::HashMap<String, crate::config::HostConfig>,
        output: crate::ssh::CommandOutput,
    ) -> crate::ports::ToolContext {
        use crate::config::{Config, SecurityConfig, SecurityMode};
        use crate::domain::{CommandHistory, ExecuteCommandUseCase, HistoryConfig, TunnelManager};
        use crate::ports::ExecutorRouter;
        use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
        use std::sync::Arc;

        let security = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: vec![],
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts,
            security: security.clone(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&security));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
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
            session_manager: Arc::new(crate::ssh::SessionManager::new(
                crate::config::SessionConfig::default(),
            )),
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
        let handler = SshFindHandler;
        let ctx = create_permissive_mock_ctx(
            server1_hosts(),
            mock_output("/var/log/syslog\n/var/log/auth.log\n/var/log/kern.log\n"),
        );
        let result = handler
            .execute(Some(json!({"host": "server1", "path": "/var/log"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
