//! SSH Tail Tool Handler
//!
//! Reads the last N lines of a remote file via SSH, with optional grep filtering.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::domain::output_truncator::truncate_output_with_cache;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::{is_retryable_error, with_retry_if};

use super::utils::shell_escape;

/// Arguments for `ssh_tail` tool
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshTailArgs {
    host: String,
    file: String,
    lines: Option<u64>,
    grep: Option<String>,
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

/// SSH Tail tool handler
#[mcp_tool(name = "ssh_tail", group = "monitoring", annotation = "read_only")]
pub struct SshTailHandler;

impl SshTailHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "file": {
                "type": "string",
                "description": "Absolute path to the file on the remote host"
            },
            "lines": {
                "type": "integer",
                "description": "Number of lines to read from end of file (default: 100)",
                "minimum": 1,
                "maximum": 100000,
                "default": 100
            },
            "grep": {
                "type": "string",
                "description": "Optional regex pattern to filter lines (applied via grep -E)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "file"]
    }"#;

    /// Build the tail command from arguments
    fn build_command(file: &str, lines: u64, grep: Option<&str>) -> String {
        grep.map_or_else(
            || format!("tail -n {lines} {}", shell_escape(file)),
            |pattern| {
                format!(
                    "tail -n {lines} {} | grep -E {}",
                    shell_escape(file),
                    shell_escape(pattern)
                )
            },
        )
    }
}

#[async_trait]
impl ToolHandler for SshTailHandler {
    fn name(&self) -> &'static str {
        "ssh_tail"
    }

    fn description(&self) -> &'static str {
        "Read the last N lines of a remote file (via tail -n), with optional regex \
         filtering (grep -E). Prefer this over ssh_exec for log reading as it shell-escapes \
         the path and pattern to prevent injection. Use grep parameter to filter lines \
         (e.g., 'ERROR|WARN' to find errors). For systemd journal logs use \
         ssh_journal_query (structured filtering by unit/priority) or ssh_journal_follow \
         (live streaming) instead. For listing directory contents use ssh_ls. For full \
         file download use ssh_download."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshTailArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Get host config
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        let lines = args.lines.unwrap_or(100);
        let command = Self::build_command(&args.file, lines, args.grep.as_deref());

        // Validate command against whitelist/blacklist
        if let Err(e) = ctx.execute_use_case.validate_builtin(&command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case
                .log_denied(self.name(), &args.host, &command, &reason);
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
            file = %args.file,
            lines = lines,
            grep = ?args.grep,
            "Tailing remote file"
        );

        // Build limits with optional timeout override
        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds {
            limits.command_timeout_seconds = timeout;
        }

        let retry_config = limits.retry_config();

        // Resolve jump host if configured
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        // Execute with retry logic
        let output = with_retry_if(
            &retry_config,
            "ssh_tail",
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
                .log_failure(self.name(), &args.host, &command, &e.to_string());
        })?;

        // Process success (audit, history, formatting, sanitization)
        let response = ctx.execute_use_case.process_success(
            self.name(),
            &args.host,
            &command,
            &output.into(),
            &[],
        );

        // Apply smart truncation with optional caching
        #[allow(clippy::cast_possible_truncation)]
        let max_chars = args
            .max_output
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);
        let truncated_stdout = truncate_output_with_cache(
            &response.stdout,
            max_chars,
            ctx.output_cache.as_deref(),
            None,
        )
        .await;

        // Save full output to local file if requested
        let mut output_text = response.format_for_llm(&truncated_stdout);
        if let Some(ref save_path) = args.save_output {
            match super::utils::save_output_to_file(save_path, &response.output).await {
                Ok(msg) => output_text = format!("{output_text}\n{msg}"),
                Err(msg) => {
                    output_text = format!("{output_text}\nsave_output error: {msg}");
                }
            }
        }

        Ok(with_exit_code_when_meaningful(
            ToolCallResult::text(output_text),
            args.grep.is_some(),
            response.exit_code,
        ))
    }
}

/// Pose le code de sortie distant, sauf quand il ne veut rien dire.
///
/// Sans `grep`, la commande est `tail -n N <fichier>` et un code non nul
/// signifie que le fichier n'a pas pu être lu. Avec `grep`, le statut du
/// pipeline est celui de `grep -E`, qui sort 1 pour « aucun match »
/// — la réponse ordinaire — et un `tail` en échec sort 1 lui aussi, donc le
/// code ne les distingue pas.
fn with_exit_code_when_meaningful(
    result: ToolCallResult,
    has_grep: bool,
    exit_code: u32,
) -> ToolCallResult {
    if has_grep || exit_code == 0 {
        return result;
    }
    result.with_remote_exit_code(i32::try_from(exit_code).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    /// Contexte avec l'hôte "server1" et une sortie distante simulée.
    fn ctx_with_output(exit_code: u32, stdout: &str, stderr: &str) -> crate::ports::ToolContext {
        let config = (*crate::ports::mock::create_test_context_with_host().config).clone();
        crate::ports::mock::create_test_context_with_config_and_mock_executor(
            config,
            crate::ssh::CommandOutput {
                exit_code,
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
                duration_ms: 1,
            },
        )
    }

    #[tokio::test]
    async fn a_failing_tail_reaches_the_caller_as_data() {
        let ctx = ctx_with_output(
            1,
            "",
            "tail: cannot open '/var/log/nope' for reading: No such file or directory",
        );
        let result = SshTailHandler
            .execute(
                Some(json!({"host": "server1", "file": "/var/log/nope"})),
                &ctx,
            )
            .await
            .expect("le handler doit rendre un résultat");
        assert_eq!(result.remote_exit_code, Some(1), "{result:?}");
    }

    #[tokio::test]
    async fn a_grep_with_no_match_is_not_a_failure() {
        // `grep -E` sort 1 pour « aucun match », qui est la réponse
        // ordinaire, et il masque en plus un échec de `tail`, qui sort 1 aussi
        // — le code ne peut pas les distinguer.
        let ctx = ctx_with_output(1, "", "");
        let result = SshTailHandler
            .execute(
                Some(json!({"host": "server1", "file": "/var/log/x", "grep": "NOPE"})),
                &ctx,
            )
            .await
            .expect("le handler doit rendre un résultat");
        assert_eq!(result.remote_exit_code, None, "{result:?}");
    }

    #[test]
    fn a_zero_exit_claims_nothing_even_without_grep() {
        // Épingle la MOITIÉ NULLE de la garde. Sans `|| exit_code == 0`, un
        // `tail` réussi porterait `Some(0)` — une affirmation que rien dans
        // l'arbre n'émet. La décision est isolée hors du handler : ce cas
        // n'a besoin d'aucun exécuteur.
        let result = with_exit_code_when_meaningful(ToolCallResult::text("ligne"), false, 0);
        assert_eq!(
            result.remote_exit_code, None,
            "un tail qui réussit ne pose aucun code : {result:?}"
        );
    }

    #[test]
    fn test_schema() {
        let handler = SshTailHandler;
        assert_eq!(handler.name(), "ssh_tail");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_tail");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("file")));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTailHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("lines"));
        assert!(properties.contains_key("grep"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTailHandler;
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
    async fn test_invalid_arguments_missing_file() {
        let handler = SshTailHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshTailHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "unknown_host",
                    "file": "/var/log/syslog"
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
        let handler = SshTailHandler;
        let ctx = create_test_context_with_host();

        // In standard mode (default), builtin tools bypass whitelist validation.
        // The command will pass validation but fail at SSH connection (expected).
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "file": "/var/log/syslog"
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
    fn test_build_command_basic() {
        let cmd = SshTailHandler::build_command("/var/log/syslog", 100, None);
        assert_eq!(cmd, "tail -n 100 '/var/log/syslog'");
    }

    #[test]
    fn test_build_command_with_grep() {
        let cmd = SshTailHandler::build_command("/var/log/syslog", 50, Some("ERROR|FATAL"));
        assert_eq!(cmd, "tail -n 50 '/var/log/syslog' | grep -E 'ERROR|FATAL'");
    }

    #[test]
    fn test_build_command_with_special_chars_in_path() {
        let cmd = SshTailHandler::build_command("/var/log/my app/test.log", 100, None);
        assert_eq!(cmd, "tail -n 100 '/var/log/my app/test.log'");
    }

    #[test]
    fn test_build_command_shell_injection_prevented() {
        let cmd = SshTailHandler::build_command("/tmp/test; rm -rf /", 100, None);
        assert_eq!(cmd, "tail -n 100 '/tmp/test; rm -rf /'");
    }

    #[test]
    fn test_build_command_grep_injection_prevented() {
        let cmd =
            SshTailHandler::build_command("/var/log/syslog", 100, Some("'; rm -rf / ; echo '"));
        assert!(cmd.contains("'\\''"));
    }
}
