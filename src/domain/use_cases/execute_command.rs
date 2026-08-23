//! Execute Command Use Case
//!
//! This use case orchestrates the execution of SSH commands,
//! handling validation, execution, sanitization, and auditing.

use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use crate::domain::CommandHistory;
use crate::error::Result;
use crate::ports::CommandOutput;
use crate::security::{AuditEvent, AuditLogger, CommandResult, CommandValidator, Sanitizer};

/// Request for executing a command
#[derive(Debug, Clone)]
pub struct ExecuteCommandRequest {
    pub host: String,
    pub command: String,
    pub timeout: Duration,
    pub working_dir: Option<String>,
}

/// Response from command execution
#[derive(Debug, Clone)]
pub struct ExecuteCommandResponse {
    pub output: String,
    pub exit_code: u32,
    pub duration_ms: u64,
    /// Sanitized stdout (separate from the formatted `output` text).
    pub stdout: String,
    /// Sanitized stderr (separate from the formatted `output` text).
    pub stderr: String,
    /// The host that executed the command.
    pub host: String,
    /// The command that was executed.
    pub command: String,
}

impl ExecuteCommandResponse {
    /// Build machine-readable structured content for AI consumption.
    ///
    /// Returns a JSON value with separated metadata and output fields,
    /// allowing AI models to parse results without text extraction.
    #[must_use]
    pub fn to_structured(&self) -> serde_json::Value {
        serde_json::json!({
            "host": self.host,
            "command": self.command,
            "exit_code": self.exit_code,
            "success": self.exit_code == 0,
            "duration_ms": self.duration_ms,
            "stdout": self.stdout,
            "stderr": self.stderr,
        })
    }

    /// Build a compact JSON string optimized for AI token consumption.
    ///
    /// Omits redundant fields the AI already knows (host, command) and
    /// skips empty fields (stdout, stderr) to minimize token usage.
    /// The `stdout` parameter allows passing a pre-truncated version.
    #[must_use]
    pub fn to_compact_json(&self, stdout_display: &str) -> String {
        let mut map = serde_json::Map::new();
        map.insert(
            "exit_code".to_string(),
            serde_json::Value::Number(self.exit_code.into()),
        );
        if !stdout_display.is_empty() {
            map.insert(
                "stdout".to_string(),
                serde_json::Value::String(stdout_display.to_string()),
            );
        }
        if !self.stderr.is_empty() {
            map.insert(
                "stderr".to_string(),
                serde_json::Value::String(self.stderr.clone()),
            );
        }
        serde_json::to_string(&map).unwrap_or_default()
    }

    /// Format output optimized for LLM token consumption.
    ///
    /// Aligned with pgEdge/Axiom best practices (2026):
    /// - Success (`exit_code`=0) + no stderr → raw stdout (zero overhead)
    /// - Success + stderr (warnings)         → stdout + `\n[stderr]\n` + stderr
    /// - Error (`exit_code`!=0)              → `[exit:N]\n` + stderr + `\n---\n` + stdout
    #[must_use]
    pub fn format_for_llm(&self, stdout_display: &str) -> String {
        if self.exit_code == 0 {
            if self.stderr.is_empty() {
                // Success, no warnings → raw stdout
                stdout_display.to_string()
            } else {
                // Success with warnings → stdout + stderr marker
                format!("{stdout_display}\n[stderr]\n{}", self.stderr)
            }
        } else if stdout_display.is_empty() {
            // Error, no stdout
            format!("[exit:{}]\n{}", self.exit_code, self.stderr)
        } else if self.stderr.is_empty() {
            // Error, no stderr (unusual but possible)
            format!("[exit:{}]\n{stdout_display}", self.exit_code)
        } else {
            // Error with both stdout and stderr
            format!(
                "[exit:{}]\n{}\n---\n{stdout_display}",
                self.exit_code, self.stderr
            )
        }
    }
}

/// Use case for executing SSH commands
///
/// This use case coordinates between the various components to:
/// 1. Validate the command against security rules
/// 2. Execute the command via SSH
/// 3. Sanitize the output
/// 4. Log the audit event
/// 5. Record in history
pub struct ExecuteCommandUseCase {
    validator: Arc<CommandValidator>,
    sanitizer: Arc<Sanitizer>,
    audit_logger: Arc<AuditLogger>,
    history: Arc<CommandHistory>,
}

impl ExecuteCommandUseCase {
    pub const fn new(
        validator: Arc<CommandValidator>,
        sanitizer: Arc<Sanitizer>,
        audit_logger: Arc<AuditLogger>,
        history: Arc<CommandHistory>,
    ) -> Self {
        Self {
            validator,
            sanitizer,
            audit_logger,
            history,
        }
    }

    /// Validate a command against security rules
    ///
    /// # Errors
    ///
    /// Returns an error if the command is denied by security rules (blacklist match or
    /// not in whitelist when in strict/standard mode).
    pub fn validate(&self, command: &str) -> Result<()> {
        self.validator.validate(command)
    }

    /// Validate a command from a trusted built-in tool handler
    ///
    /// Only checks blacklist, skips whitelist validation. Used by specialized
    /// tool handlers that construct commands via trusted domain command builders.
    ///
    /// # Errors
    ///
    /// Returns an error if the command is denied by blacklist rules.
    pub fn validate_builtin(&self, command: &str) -> Result<()> {
        self.validator.validate_builtin(command)
    }

    /// Log a denied command
    pub fn log_denied(&self, host: &str, command: &str, reason: &str) {
        self.audit_logger
            .log(AuditEvent::denied(host, command, reason));
    }

    /// Process the output from a successful command execution
    #[must_use]
    pub fn process_success(
        &self,
        host: &str,
        command: &str,
        output: &CommandOutput,
    ) -> ExecuteCommandResponse {
        // Redact secrets (e.g. an AWX bearer token typed on the command line)
        // from the command itself before it ever reaches audit or history —
        // both re-export `command` verbatim, and only the *output* used to be
        // sanitized (audit 2026-08-13, B5/B6).
        let redacted = self.sanitizer.sanitize(command);

        self.record_success_redacted(host, &redacted, output.exit_code, output.duration_ms);

        // Format and sanitize the result. Pass the already-redacted command so
        // the raw value never appears in `result` even transiently — the
        // outer `sanitize(&result)` below still runs (it has stdout/stderr
        // secrets to catch), but the "no raw command past this point"
        // invariant no longer depends on that second pass alone.
        let result = Self::format_output(host, &redacted, output);
        let sanitized = self.sanitizer.sanitize(&result).into_owned();

        // Also sanitize stdout/stderr separately for structured content
        let sanitized_stdout = self.sanitizer.sanitize(&output.stdout).into_owned();
        let sanitized_stderr = self.sanitizer.sanitize(&output.stderr).into_owned();

        ExecuteCommandResponse {
            output: sanitized,
            exit_code: output.exit_code,
            duration_ms: output.duration_ms,
            stdout: sanitized_stdout,
            stderr: sanitized_stderr,
            host: host.to_string(),
            command: redacted.into_owned(),
        }
    }

    /// Record a successful command whose output the caller formats itself.
    ///
    /// `process_success` also formats, sanitizes and returns a response. A
    /// persistent session already does all three, so it needs only the
    /// audit-and-history half — without it a session command that succeeds
    /// leaves no trace anywhere, while the same command denied does.
    pub fn log_success(&self, host: &str, command: &str, exit_code: u32, duration_ms: u64) {
        let redacted = self.sanitizer.sanitize(command);
        self.record_success_redacted(host, &redacted, exit_code, duration_ms);
    }

    /// Audit + history for a command whose text is ALREADY redacted.
    ///
    /// Both callers redact first — `process_success` because it reuses the
    /// redacted text for formatting, `log_success` because it has nothing
    /// else to do with it. Taking the redacted form as a parameter keeps the
    /// "no raw command past this point" invariant on one line each.
    fn record_success_redacted(
        &self,
        host: &str,
        redacted: &str,
        exit_code: u32,
        duration_ms: u64,
    ) {
        self.audit_logger.log(AuditEvent::new(
            host,
            redacted,
            CommandResult::Success {
                exit_code,
                duration_ms,
            },
        ));
        self.history
            .record_success(host, redacted, exit_code, duration_ms);
    }

    /// Log a failed command execution
    pub fn log_failure(&self, host: &str, command: &str, error: &str) {
        // Same redaction as `process_success` — see its comment.
        let redacted = self.sanitizer.sanitize(command);

        self.audit_logger.log(AuditEvent::new(
            host,
            &redacted,
            CommandResult::Error {
                message: error.to_string(),
            },
        ));

        self.history.record_failure(host, &redacted);
    }

    /// Format command output for display
    fn format_output(host: &str, command: &str, output: &CommandOutput) -> String {
        let mut result = String::new();
        let exit_code = output.exit_code;
        let duration_ms = output.duration_ms;

        let _ = writeln!(result, "Host: {host}");
        let _ = writeln!(result, "Command: {command}");
        let _ = writeln!(result, "Exit code: {exit_code}");
        let _ = writeln!(result, "Duration: {duration_ms}ms");
        let _ = writeln!(result, "\n--- STDOUT ---");
        result.push_str(&output.stdout);

        if !output.stderr.is_empty() {
            let _ = writeln!(result, "\n--- STDERR ---");
            result.push_str(&output.stderr);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SecurityConfig, SecurityMode};
    use crate::domain::HistoryConfig;
    use crate::security::CommandValidator;

    fn create_test_use_case() -> ExecuteCommandUseCase {
        let security_config = crate::config::SecurityConfig::default();

        ExecuteCommandUseCase::new(
            Arc::new(CommandValidator::new(&security_config)),
            Arc::new(Sanitizer::with_defaults()),
            Arc::new(AuditLogger::disabled()),
            Arc::new(CommandHistory::new(&HistoryConfig::default())),
        )
    }

    fn create_permissive_use_case() -> ExecuteCommandUseCase {
        let security_config = crate::config::SecurityConfig {
            mode: SecurityMode::Permissive,
            ..Default::default()
        };

        ExecuteCommandUseCase::new(
            Arc::new(CommandValidator::new(&security_config)),
            Arc::new(Sanitizer::with_defaults()),
            Arc::new(AuditLogger::disabled()),
            Arc::new(CommandHistory::new(&HistoryConfig::default())),
        )
    }

    #[test]
    fn test_validate_command() {
        let use_case = create_test_use_case();

        // In strict mode with empty whitelist, commands should be denied
        assert!(use_case.validate("ls -la").is_err());
    }

    #[test]
    fn test_validate_command_permissive() {
        let use_case = create_permissive_use_case();

        // In permissive mode, commands should be allowed
        assert!(use_case.validate("ls -la").is_ok());
        assert!(use_case.validate("echo hello").is_ok());
    }

    #[test]
    fn test_format_output() {
        let output = CommandOutput {
            stdout: "file1.txt\nfile2.txt\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 100,
        };

        let formatted = ExecuteCommandUseCase::format_output("test-host", "ls", &output);

        assert!(formatted.contains("Host: test-host"));
        assert!(formatted.contains("Command: ls"));
        assert!(formatted.contains("Exit code: 0"));
        assert!(formatted.contains("Duration: 100ms"));
        assert!(formatted.contains("file1.txt"));
        assert!(formatted.contains("--- STDOUT ---"));
    }

    #[test]
    fn test_format_output_with_stderr() {
        let output = CommandOutput {
            stdout: "output".to_string(),
            stderr: "warning: something".to_string(),
            exit_code: 0,
            duration_ms: 50,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "cmd", &output);

        assert!(formatted.contains("--- STDOUT ---"));
        assert!(formatted.contains("--- STDERR ---"));
        assert!(formatted.contains("warning: something"));
    }

    #[test]
    fn test_format_output_empty_stdout() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "true", &output);

        assert!(formatted.contains("Host: host"));
        assert!(formatted.contains("Exit code: 0"));
        assert!(formatted.contains("--- STDOUT ---"));
        assert!(!formatted.contains("--- STDERR ---")); // No stderr section for empty stderr
    }

    #[test]
    fn test_format_output_nonzero_exit() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: "command not found".to_string(),
            exit_code: 127,
            duration_ms: 5,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "nonexistent", &output);

        assert!(formatted.contains("Exit code: 127"));
        assert!(formatted.contains("command not found"));
    }

    #[test]
    fn test_to_compact_json_success() {
        let resp = ExecuteCommandResponse {
            output: "formatted".to_string(),
            exit_code: 0,
            duration_ms: 42,
            stdout: "hello world".to_string(),
            stderr: String::new(),
            host: "server1".to_string(),
            command: "echo hello".to_string(),
        };

        let json = resp.to_compact_json(&resp.stdout);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["exit_code"], 0);
        assert_eq!(parsed["stdout"], "hello world");
        assert!(parsed.get("stderr").is_none()); // empty stderr omitted
        assert!(parsed.get("host").is_none()); // host omitted
        assert!(parsed.get("command").is_none()); // command omitted
        assert!(parsed.get("duration_ms").is_none()); // duration omitted
    }

    #[test]
    fn test_to_compact_json_error() {
        let resp = ExecuteCommandResponse {
            output: "formatted".to_string(),
            exit_code: 127,
            duration_ms: 5,
            stdout: String::new(),
            stderr: "command not found".to_string(),
            host: "server2".to_string(),
            command: "nonexistent".to_string(),
        };

        let json = resp.to_compact_json(&resp.stdout);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["exit_code"], 127);
        assert!(parsed.get("stdout").is_none()); // empty stdout omitted
        assert_eq!(parsed["stderr"], "command not found");
    }

    #[test]
    fn test_to_compact_json_truncated_stdout() {
        let resp = ExecuteCommandResponse {
            output: "formatted".to_string(),
            exit_code: 0,
            duration_ms: 42,
            stdout: "full output".to_string(),
            stderr: String::new(),
            host: "server1".to_string(),
            command: "echo hello".to_string(),
        };

        let json = resp.to_compact_json("truncated output");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["stdout"], "truncated output");
    }

    #[test]
    fn test_to_compact_json_empty() {
        let resp = ExecuteCommandResponse {
            output: "formatted".to_string(),
            exit_code: 0,
            duration_ms: 10,
            stdout: String::new(),
            stderr: String::new(),
            host: "host".to_string(),
            command: "true".to_string(),
        };

        let json = resp.to_compact_json(&resp.stdout);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["exit_code"], 0);
        assert!(parsed.get("stdout").is_none());
        assert!(parsed.get("stderr").is_none());
    }

    // ============== format_for_llm Tests ==============

    #[test]
    fn test_format_for_llm_success() {
        let resp = ExecuteCommandResponse {
            output: String::new(),
            exit_code: 0,
            duration_ms: 42,
            stdout: "hello world".to_string(),
            stderr: String::new(),
            host: "server1".to_string(),
            command: "echo hello".to_string(),
        };

        let result = resp.format_for_llm(&resp.stdout);
        assert_eq!(result, "hello world"); // raw stdout, no wrapping
    }

    #[test]
    fn test_format_for_llm_success_with_stderr() {
        let resp = ExecuteCommandResponse {
            output: String::new(),
            exit_code: 0,
            duration_ms: 42,
            stdout: "output data".to_string(),
            stderr: "warning: deprecated".to_string(),
            host: "server1".to_string(),
            command: "cmd".to_string(),
        };

        let result = resp.format_for_llm(&resp.stdout);
        assert!(result.starts_with("output data"));
        assert!(result.contains("[stderr]"));
        assert!(result.contains("warning: deprecated"));
    }

    #[test]
    fn test_format_for_llm_error() {
        let resp = ExecuteCommandResponse {
            output: String::new(),
            exit_code: 127,
            duration_ms: 5,
            stdout: "partial output".to_string(),
            stderr: "command not found".to_string(),
            host: "server2".to_string(),
            command: "nonexistent".to_string(),
        };

        let result = resp.format_for_llm(&resp.stdout);
        assert!(result.starts_with("[exit:127]"));
        assert!(result.contains("command not found"));
        assert!(result.contains("partial output"));
    }

    #[test]
    fn test_format_for_llm_error_no_stdout() {
        let resp = ExecuteCommandResponse {
            output: String::new(),
            exit_code: 1,
            duration_ms: 5,
            stdout: String::new(),
            stderr: "error occurred".to_string(),
            host: "host".to_string(),
            command: "cmd".to_string(),
        };

        let result = resp.format_for_llm(&resp.stdout);
        assert_eq!(result, "[exit:1]\nerror occurred");
    }

    #[test]
    fn test_format_for_llm_empty() {
        let resp = ExecuteCommandResponse {
            output: String::new(),
            exit_code: 0,
            duration_ms: 10,
            stdout: String::new(),
            stderr: String::new(),
            host: "host".to_string(),
            command: "true".to_string(),
        };

        let result = resp.format_for_llm(&resp.stdout);
        assert_eq!(result, ""); // empty string, no wrapping
    }

    #[test]
    fn test_format_for_llm_truncated_stdout() {
        let resp = ExecuteCommandResponse {
            output: String::new(),
            exit_code: 0,
            duration_ms: 42,
            stdout: "full output here".to_string(),
            stderr: String::new(),
            host: "server1".to_string(),
            command: "cmd".to_string(),
        };

        let result = resp.format_for_llm("truncated...");
        assert_eq!(result, "truncated..."); // uses truncated version
    }

    #[test]
    fn test_process_success() {
        let use_case = create_test_use_case();

        let output = CommandOutput {
            stdout: "password=secret123".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 50,
        };

        let response = use_case.process_success("host", "echo test", &output);

        // Password should be sanitized
        assert!(!response.output.contains("secret123"));
        assert!(response.output.contains("[REDACTED]"));
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.duration_ms, 50);
    }

    #[test]
    fn log_success_records_history_without_formatting() {
        let security = SecurityConfig {
            mode: SecurityMode::Permissive,
            ..SecurityConfig::default()
        };
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
        let use_case = ExecuteCommandUseCase::new(
            Arc::new(CommandValidator::new(&security)),
            Arc::new(Sanitizer::with_defaults()),
            Arc::new(AuditLogger::disabled()),
            Arc::clone(&history),
        );

        use_case.log_success("raspberry", "uptime", 0, 12);

        let entries = history.recent(10);
        assert_eq!(
            entries.len(),
            1,
            "a successful session command must leave a history entry"
        );
        assert_eq!(entries[0].host, "raspberry");
        assert_eq!(entries[0].command, "uptime");
        assert_eq!(entries[0].exit_code, 0);
    }

    #[test]
    fn test_process_success_with_api_key() {
        let use_case = create_test_use_case();

        // GitHub PAT pattern: ghp_ followed by exactly 36 alphanumeric chars
        let token = "ghp_1234567890abcdefGHIJKLmnopqrstuvwxyz";
        let output = CommandOutput {
            stdout: format!("GITHUB_TOKEN={token}"),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let response = use_case.process_success("host", "env", &output);

        // GitHub token should be sanitized
        assert!(!response.output.contains(token));
    }

    #[test]
    fn test_process_success_nonzero_exit() {
        let use_case = create_test_use_case();

        let output = CommandOutput {
            stdout: String::new(),
            stderr: "Error occurred".to_string(),
            exit_code: 1,
            duration_ms: 100,
        };

        let response = use_case.process_success("host", "failing_cmd", &output);

        assert_eq!(response.exit_code, 1);
        assert!(response.output.contains("Error occurred"));
    }

    #[test]
    fn test_log_denied_does_not_panic() {
        let use_case = create_test_use_case();

        // Should not panic even with disabled logger
        use_case.log_denied("host1", "rm -rf /", "blacklisted");
        use_case.log_denied("host2", "dangerous_command", "not in whitelist");
    }

    #[test]
    fn test_log_failure_does_not_panic() {
        let use_case = create_test_use_case();

        // Should not panic even with disabled logger
        use_case.log_failure("host1", "ls", "connection timeout");
        use_case.log_failure("host2", "pwd", "network error");
    }

    #[test]
    fn test_execute_command_request_clone() {
        let req = ExecuteCommandRequest {
            host: "test".to_string(),
            command: "ls".to_string(),
            timeout: Duration::from_secs(30),
            working_dir: Some("/tmp".to_string()),
        };

        let cloned = req.clone();
        assert_eq!(req.host, cloned.host);
        assert_eq!(req.command, cloned.command);
        assert_eq!(req.timeout, cloned.timeout);
        assert_eq!(req.working_dir, cloned.working_dir);
    }

    #[test]
    fn test_execute_command_request_debug() {
        let req = ExecuteCommandRequest {
            host: "test".to_string(),
            command: "ls".to_string(),
            timeout: Duration::from_secs(30),
            working_dir: None,
        };

        let debug_str = format!("{req:?}");
        assert!(debug_str.contains("ExecuteCommandRequest"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_execute_command_response_clone() {
        let resp = ExecuteCommandResponse {
            output: "result".to_string(),
            exit_code: 0,
            duration_ms: 100,
            stdout: "result".to_string(),
            stderr: String::new(),
            host: "host".to_string(),
            command: "ls".to_string(),
        };

        let cloned = resp.clone();
        assert_eq!(resp.output, cloned.output);
        assert_eq!(resp.exit_code, cloned.exit_code);
        assert_eq!(resp.duration_ms, cloned.duration_ms);
        assert_eq!(resp.stdout, cloned.stdout);
        assert_eq!(resp.stderr, cloned.stderr);
        assert_eq!(resp.host, cloned.host);
        assert_eq!(resp.command, cloned.command);
    }

    #[test]
    fn test_execute_command_response_debug() {
        let resp = ExecuteCommandResponse {
            output: "result".to_string(),
            exit_code: 42,
            duration_ms: 100,
            stdout: "result".to_string(),
            stderr: String::new(),
            host: "host".to_string(),
            command: "cmd".to_string(),
        };

        let debug_str = format!("{resp:?}");
        assert!(debug_str.contains("ExecuteCommandResponse"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_to_structured() {
        let resp = ExecuteCommandResponse {
            output: "formatted".to_string(),
            exit_code: 0,
            duration_ms: 42,
            stdout: "hello world".to_string(),
            stderr: String::new(),
            host: "server1".to_string(),
            command: "echo hello".to_string(),
        };

        let structured = resp.to_structured();
        assert_eq!(structured["host"], "server1");
        assert_eq!(structured["command"], "echo hello");
        assert_eq!(structured["exit_code"], 0);
        assert_eq!(structured["success"], true);
        assert_eq!(structured["duration_ms"], 42);
        assert_eq!(structured["stdout"], "hello world");
        assert_eq!(structured["stderr"], "");
    }

    #[test]
    fn test_to_structured_failure() {
        let resp = ExecuteCommandResponse {
            output: "formatted".to_string(),
            exit_code: 127,
            duration_ms: 5,
            stdout: String::new(),
            stderr: "command not found".to_string(),
            host: "server2".to_string(),
            command: "nonexistent".to_string(),
        };

        let structured = resp.to_structured();
        assert_eq!(structured["success"], false);
        assert_eq!(structured["exit_code"], 127);
        assert_eq!(structured["stderr"], "command not found");
    }

    #[test]
    fn test_format_output_unicode() {
        let output = CommandOutput {
            stdout: "日本語テスト\n中文输出\n🎉".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "echo", &output);

        assert!(formatted.contains("日本語テスト"));
        assert!(formatted.contains("中文输出"));
        assert!(formatted.contains("🎉"));
    }

    #[test]
    fn test_format_output_long_command() {
        let output = CommandOutput {
            stdout: "ok".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let long_cmd = "find / -name '*.log' -exec grep -l 'error' {} \\; | head -n 100";
        let formatted = ExecuteCommandUseCase::format_output("host", long_cmd, &output);

        assert!(formatted.contains(long_cmd));
    }

    #[test]
    fn test_format_output_special_chars() {
        let output = CommandOutput {
            stdout: "line1\tline2\rline3\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "cmd", &output);

        assert!(formatted.contains("line1\t"));
        assert!(formatted.contains("\rline3"));
    }
}
