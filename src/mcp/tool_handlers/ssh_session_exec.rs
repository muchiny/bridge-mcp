//! SSH Session Exec Tool Handler
//!
//! Executes a command in an existing persistent shell session.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::domain::output_truncator::truncate_output_with_cache;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

use crate::config::{HostConfig, ShellType};

use super::utils::shell_escape;

/// Arguments for `ssh_session_exec` tool
#[derive(Debug, Deserialize)]
struct SshSessionExecArgs {
    session_id: String,
    command: String,
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    sudo: Option<bool>,
    sudo_user: Option<String>,
    save_output: Option<String>,
}

/// SSH Session Exec tool handler
#[mcp_tool(name = "ssh_session_exec", group = "sessions", annotation = "mutating")]
pub struct SshSessionExecHandler;

impl SshSessionExecHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "session_id": {
                "type": "string",
                "description": "The session ID (id field) returned by ssh_session_create or found via ssh_session_list"
            },
            "command": {
                "type": "string",
                "description": "The command to execute in the session"
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
                "description": "Absolute path on the bridge-mcp host filesystem to save the full untruncated output. Claude Code (running on the same machine as the bridge) can then read this file with its Read tool."
            },
            "sudo": {
                "type": "boolean",
                "description": "Run the command with sudo (default: false)"
            },
            "sudo_user": {
                "type": "string",
                "description": "User to run sudo as (default: root)"
            }
        },
        "required": ["session_id", "command"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshSessionExecHandler {
    fn name(&self) -> &'static str {
        "ssh_session_exec"
    }

    fn description(&self) -> &'static str {
        "Execute a command inside an existing persistent shell session (created by \
         ssh_session_create). Unlike ssh_exec (stateless, one-shot), the session retains \
         working directory and environment variables between calls — ideal for multi-step \
         workflows such as 'cd /app', then 'npm install', then 'npm run build'. Returns JSON \
         with fields: session_id, exit_code, cwd (updated after cd commands), output. Obtain \
         session_id from ssh_session_create or ssh_session_list. Use ssh_session_close when \
         the workflow is complete."
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
        let args: SshSessionExecArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Validate command against whitelist/blacklist
        if let Err(e) = ctx.execute_use_case.validate(&args.command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case
                .log_denied("session", &args.command, &reason);
            return Err(e);
        }

        let timeout_secs = args
            .timeout_seconds
            .unwrap_or(ctx.config.limits.command_timeout_seconds);

        // Resolve host config for this session (needed for sudo and shell type)
        let session_host_name = ctx.session_manager.get_session_host(&args.session_id).await;
        let session_host_config = session_host_name
            .as_ref()
            .and_then(|name| ctx.config.hosts.get(name));
        let effective_shell =
            session_host_config.map_or(ShellType::Posix, HostConfig::effective_shell);

        // Wrap command with sudo if requested (POSIX only; no-op on Windows)
        let command = if args.sudo.unwrap_or(false) && effective_shell == ShellType::Posix {
            let sudo_user = args.sudo_user.as_deref().unwrap_or("root");
            let sudo_password = session_host_config.and_then(|h| h.sudo_password.clone());

            if let Some(ref password) = sudo_password {
                tracing::warn!(
                    "Using sudo with password via stdin. \
                     Consider configuring NOPASSWD in sudoers for better security."
                );
                // Use printf in a subshell to reduce password visibility in process list
                format!(
                    "printf '%s\\n' {} | sudo -S -u {} {}",
                    shell_escape(password),
                    shell_escape(sudo_user),
                    args.command
                )
            } else {
                format!("sudo -n -u {} {}", shell_escape(sudo_user), args.command)
            }
        } else {
            args.command.clone()
        };

        info!(
            session_id = %args.session_id,
            command = %args.command,
            "Executing command in session"
        );

        let result = ctx
            .session_manager
            .exec(&args.session_id, &command, timeout_secs)
            .await?;

        if result.exit_code != 0 {
            warn!(
                session_id = %args.session_id,
                command = %args.command,
                exit_code = result.exit_code,
                "Session command failed"
            );
        }

        // Sanitize output
        let sanitized_output = ctx.sanitizer.sanitize(&result.output);

        // Apply smart truncation with optional caching
        #[allow(clippy::cast_possible_truncation)]
        let max_chars = args
            .max_output
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);
        let output_text =
            truncate_output_with_cache(&sanitized_output, max_chars, ctx.output_cache.as_deref())
                .await;

        // Build response with metadata
        let response = serde_json::json!({
            "session_id": result.session_id,
            "exit_code": result.exit_code,
            "cwd": result.cwd,
            "output": output_text,
        });

        let mut json = serde_json::to_string(&response)
            .unwrap_or_else(|e| format!("Error serializing result: {e}"));

        // Save full output to local file if requested
        if let Some(ref save_path) = args.save_output {
            match super::utils::save_output_to_file(save_path, &sanitized_output).await {
                Ok(msg) => json = format!("{json}\n{msg}"),
                Err(msg) => json = format!("{json}\nsave_output error: {msg}"),
            }
        }

        Ok(ToolCallResult::text(json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, Config, HttpTransportConfig, LimitsConfig, SecurityConfig, SecurityMode,
        SessionConfig, SshConfigDiscovery, ToolGroupsConfig,
    };
    use crate::domain::{ExecuteCommandUseCase, TunnelManager};
    use crate::mcp::CommandHistory;
    use crate::mcp::history::HistoryConfig;
    use crate::ports::ExecutorRouter;
    use crate::ports::ToolContext;
    use crate::ports::mock::create_test_context;
    use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
    use crate::ssh::SessionManager;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Create a test context with permissive security so commands pass validation
    fn create_permissive_context() -> ToolContext {
        let security = SecurityConfig {
            mode: SecurityMode::Permissive,
            ..SecurityConfig::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: security.clone(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
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

        ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::with_defaults()),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
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

    #[test]
    fn test_schema() {
        let handler = SshSessionExecHandler;
        assert_eq!(handler.name(), "ssh_session_exec");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_session_exec");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("session_id")));
        assert!(required.contains(&json!("command")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSessionExecHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_session_not_found() {
        let handler = SshSessionExecHandler;
        let ctx = create_permissive_context();

        let result = handler
            .execute(
                Some(json!({
                    "session_id": "nonexistent-id",
                    "command": "ls"
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "nonexistent-id");
            }
            e => panic!("Expected SessionNotFound, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_arguments() {
        let handler = SshSessionExecHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"session_id": "test"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_command_denied() {
        let handler = SshSessionExecHandler;
        let ctx = create_test_context();

        // In strict mode (default), commands not in whitelist are denied
        let result = handler
            .execute(
                Some(json!({
                    "session_id": "test-session",
                    "command": "rm -rf /"
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }
}
