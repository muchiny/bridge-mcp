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

    /// Log a denied command, recording which tool asked for it.
    ///
    /// `tool` is mandatory, and the criterion is this: **`event_type` names a
    /// kind of outcome, and no reader may take it for the tool that produced
    /// it.** No entry point on this type can make it name the tool —
    /// `AuditEvent::denied`, which this one uses, hard-codes
    /// `"command_denied"`; `AuditEvent::new`, which the others use,
    /// hard-codes `"ssh_exec"`; and the one constructor that takes the value,
    /// `AuditEvent::tagged`, is reached only through a facade here that passes
    /// a kind of its own (`"state_change"`). The criterion holds for every
    /// entry point present and for any entry point added, as long as that
    /// stays true — which is its bound, and the only thing a later reader has
    /// to re-check.
    ///
    /// **One of those three values is also a tool name, and that is the
    /// point, not an exception to it.** `"ssh_exec"` is a kind of outcome
    /// here — "a command ran on a host" — but it is spelled exactly like the
    /// tool `ssh_exec`, so for that one tool `event_type == tool_name`
    /// coincidentally, and for the 475 others it reads the same while naming
    /// a different tool. A field that is right by accident for one tool out
    /// of 476 is worse than one that is always wrong, because it invites the
    /// inference. Without `tool`, then, an audit line could not say whether a
    /// denial came from `ssh_exec` itself or from `ssh_file_write`.
    /// `tool_name` has existed on the event since it was added, but as long
    /// as carrying it was optional nothing in
    /// production ever set it: a 2026-09 measurement found 25% of 3,686
    /// audit lines with no `tool_name`, and `ssh_exec` — the escape hatch
    /// every free-form write goes through — never appeared as a tool name
    /// at all. An absent name proved nothing; it only meant a caller had
    /// not bothered.
    pub fn log_denied(&self, tool: &str, host: &str, command: &str, reason: &str) {
        self.audit_logger
            .log(tool, AuditEvent::denied(host, command, reason));
    }

    /// Process a successful execution, recording which tool ran it.
    ///
    /// See [`Self::log_denied`] for why `tool` is mandatory rather than an
    /// `Option`.
    #[must_use]
    pub fn process_success(
        &self,
        tool: &str,
        host: &str,
        command: &str,
        output: &CommandOutput,
        reduction: &[&'static str],
    ) -> ExecuteCommandResponse {
        // Redact secrets (e.g. an AWX bearer token typed on the command line)
        // from the command itself before it ever reaches audit or history —
        // both re-export `command` verbatim, and only the *output* used to be
        // sanitized (audit 2026-08-13, B5/B6).
        let redacted = self.sanitizer.sanitize(command);
        self.record_success_redacted(
            tool,
            host,
            &redacted,
            output.exit_code,
            output.duration_ms,
            reduction,
        );
        self.finish_success(host, &redacted, output)
    }

    /// Format and sanitize a successful result, after it has been recorded.
    ///
    /// Split out so the tool-named variant records a different audit event
    /// without duplicating any of this.
    ///
    /// Takes the already-redacted command so the raw value never appears in
    /// `result` even transiently — the outer `sanitize(&result)` still runs (it
    /// has stdout/stderr secrets to catch), but the "no raw command past this
    /// point" invariant no longer depends on that second pass alone.
    fn finish_success(
        &self,
        host: &str,
        redacted: &str,
        output: &CommandOutput,
    ) -> ExecuteCommandResponse {
        let result = Self::format_output(host, redacted, output);
        let sanitized = self.sanitizer.sanitize(&result).into_owned();

        let sanitized_stdout = self.sanitizer.sanitize(&output.stdout).into_owned();
        let sanitized_stderr = self.sanitizer.sanitize(&output.stderr).into_owned();

        ExecuteCommandResponse {
            output: sanitized,
            exit_code: output.exit_code,
            duration_ms: output.duration_ms,
            stdout: sanitized_stdout,
            stderr: sanitized_stderr,
            host: host.to_string(),
            command: redacted.to_string(),
        }
    }

    /// Record a successful command whose output the caller formats itself.
    ///
    /// `process_success` also formats, sanitizes and returns a response. A
    /// persistent session already does all three, so it needs only the
    /// audit-and-history half — without it a session command that succeeds
    /// leaves no trace anywhere, while the same command denied does.
    ///
    /// `tool` is mandatory — see [`Self::log_denied`]. This is the entry
    /// point the persistent-session path uses, and it was the one bare call
    /// with no tool-named twin at all: `ssh_session_exec` never once
    /// appeared as a tool name in the audit log this task was written to
    /// fix.
    pub fn log_success(
        &self,
        tool: &str,
        host: &str,
        command: &str,
        exit_code: u32,
        duration_ms: u64,
    ) {
        let redacted = self.sanitizer.sanitize(command);
        self.record_success_redacted(tool, host, &redacted, exit_code, duration_ms, &[]);
    }

    /// Audit + history for a command whose text is ALREADY redacted.
    ///
    /// Both callers redact first — `process_success` because it reuses the
    /// redacted text for formatting, `log_success` because it has nothing
    /// else to do with it. Taking the redacted form as a parameter keeps the
    /// "no raw command past this point" invariant on one line each.
    fn record_success_redacted(
        &self,
        tool: &str,
        host: &str,
        redacted: &str,
        exit_code: u32,
        duration_ms: u64,
        reduction: &[&'static str],
    ) {
        let mut event = AuditEvent::new(
            host,
            redacted,
            CommandResult::Success {
                exit_code,
                duration_ms,
            },
        );
        event.reduction = reduction.to_vec();
        self.audit_logger.log(tool, event);
        self.history
            .record_success(host, redacted, exit_code, duration_ms);
    }

    /// Record a server-state change that ran no process, naming the tool.
    ///
    /// The fifth entry point, for the operations whose whole effect is on the
    /// bridge or on the SSH transport — a session or tunnel opened or closed,
    /// a recording started or stopped, a runtime limit set. Seven tools did
    /// all of that and wrote **nothing**: measured live, `ssh_session_create`
    /// followed by `ssh_session_close` against a real host produced zero audit
    /// lines, so a persistent remote shell was created and destroyed without
    /// the trail saying so.
    ///
    /// `tool` is mandatory — see [`Self::log_denied`]. `operation` is the tool
    /// and its identifying argument (`ssh_session_close session_id=…`), which
    /// is what the event's `command` field carries; `host` is a real alias
    /// whenever one is resolvable and [`crate::security::NO_HOST`] when the
    /// operation has no target at all.
    ///
    /// Callers build the tool part of `operation` from `self.name()`, not
    /// from a literal. `tool` above comes from `self.name()` too, and
    /// `registry.rs` keys the tool registry on `handler.name()`, so `name()`
    /// is the authority: two sources for the same string inside one call is a
    /// divergence waiting to happen, and here the two strings end up in two
    /// fields of the same line.
    ///
    /// **No history entry on this path, and that is the reason this is not
    /// [`Self::log_success`].** `HistoryEntry` (`src/domain/history.rs`) has a
    /// non-optional `exit_code: u32` and derives `success` from `exit_code ==
    /// 0`, so recording a state change there would have to invent the very
    /// `0` that [`CommandResult::StateChanged`] exists to refuse. The audit
    /// trail can say "state changed, no code"; the command history cannot say
    /// it at all, and it is a history of *commands*.
    ///
    /// **The asymmetry that follows, written down because it reads like an
    /// oversight and is not one:** when the state-changing call itself
    /// returns `Err` — `SessionManager::close`, `TunnelManager::register`,
    /// `SessionRecorder::stop_session` and their siblings — the handler goes
    /// through [`Self::log_failure`], which writes audit **and** history. So
    /// `ssh_history` and `history://recent` show *some* failures of these
    /// seven tools and **never** a success. That is more misleading than a
    /// clean absence, and it is deliberate: the alternative is either a
    /// fabricated `exit_code` on the success path or dropping failure lines
    /// that exist today.
    ///
    /// *Some*, and the bound matters, because an earlier version of this
    /// paragraph said the seven write history "when they fail" flatly and
    /// that was measured false. Everything refused **before** that call
    /// writes nothing at all, to either sink: malformed arguments, an unknown
    /// host, a rate-limit refusal, a disabled recorder or a missing runtime
    /// handle — and, in `ssh_tunnel_create`, a failed `TcpListener::bind` or
    /// a failed SSH connection, measured with `local_port=80` as zero new
    /// lines in the journal. `ssh_config_set` has no such call at all: both
    /// of its non-success outcomes are refusals that changed nothing, so it
    /// never reaches `log_failure`.
    ///
    /// `audit.log` is therefore the fuller record for these seven, and the
    /// command history is not — but neither is complete, and no reader should
    /// take either for a count of attempts.
    pub fn log_state_change(&self, tool: &str, host: &str, operation: &str, duration_ms: u64) {
        // Same redaction as `process_success` — see its comment. An operation
        // string is built from tool arguments, and `ssh_config_set` passes a
        // key and a value.
        let redacted = self.sanitizer.sanitize(operation);

        self.audit_logger.log(
            tool,
            AuditEvent::tagged(
                "state_change",
                host,
                &redacted,
                CommandResult::StateChanged { duration_ms },
            ),
        );
    }

    /// Log a failed command execution, recording which tool ran it.
    ///
    /// `tool` is mandatory — see [`Self::log_denied`].
    pub fn log_failure(&self, tool: &str, host: &str, command: &str, error: &str) {
        // Same redaction as `process_success` — see its comment.
        let redacted = self.sanitizer.sanitize(command);

        self.audit_logger.log(
            tool,
            AuditEvent::new(
                host,
                &redacted,
                CommandResult::Error {
                    message: error.to_string(),
                },
            ),
        );

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
    use crate::security::{CommandValidator, NO_HOST};

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

    /// Like `create_test_use_case`, but wired to an `AuditLogger::for_test`
    /// instead of `AuditLogger::disabled` so a test can drain and assert on
    /// the exact `AuditEvent`s a call produced (`tool_name` included).
    fn test_use_case() -> ExecuteCommandUseCase {
        let security_config = crate::config::SecurityConfig::default();

        ExecuteCommandUseCase::new(
            Arc::new(CommandValidator::new(&security_config)),
            Arc::new(Sanitizer::with_defaults()),
            Arc::new(AuditLogger::for_test()),
            Arc::new(CommandHistory::new(&HistoryConfig::default())),
        )
    }

    /// A remote failure must be readable as **data** — `exit_code` on the
    /// response — not only as the `[exit:N]` prefix `format_for_llm` writes
    /// into the text a human reads.
    ///
    /// The field already exists and `finish_success` already fills it, so
    /// this test is a **lock, not a driver**: it pins the data path so a
    /// later change cannot quietly turn the remote exit code back into
    /// presentation only. The genuine red for this task is one layer up, in
    /// `cli::runner`, where the code was being dropped on the floor.
    #[test]
    fn a_remote_failure_is_visible_as_data_not_only_as_text() {
        let uc = test_use_case();
        let out = CommandOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "no such user".into(),
            duration_ms: 1,
        };
        let resp = uc.process_success("ssh_user_info", "raspberry", "id btest", &out, &[]);
        assert_eq!(
            resp.exit_code, 1,
            "the remote exit code must be data, not only a text prefix"
        );
        // The text is unchanged: `format_for_llm` still leads with the
        // `[exit:N]` marker. Note it is `format_for_llm` that carries that
        // prefix, not `resp.output` — the latter is `format_output`'s
        // verbose `Host:/Command:/Exit code:` block.
        let text = resp.format_for_llm(&resp.stdout);
        assert!(
            text.starts_with("[exit:1]"),
            "the [exit:N] text stays for the reader, got {text:?}"
        );
    }

    #[test]
    fn every_audit_event_carries_the_tool_that_produced_it() {
        let uc = test_use_case();
        let out = CommandOutput {
            exit_code: 0,
            stdout: "x".into(),
            stderr: String::new(),
            duration_ms: 1,
        };
        let _ = uc.process_success("ssh_exec", "raspberry", "id", &out, &[]);
        let events = uc.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].tool_name.as_deref(),
            Some("ssh_exec"),
            "un événement d'audit sans nom d'outil n'est rattachable à rien"
        );
    }

    /// The seven state tools wrote nothing at all; the point of the fifth
    /// entry point is that what they now write carries the tool, the
    /// operation, and **no exit code**, because none of them runs a process.
    #[test]
    fn a_state_change_is_audited_with_its_tool_and_without_an_exit_code() {
        let uc = test_use_case();
        uc.log_state_change(
            "ssh_session_create",
            "raspberry",
            "ssh_session_create session_id=sess-1",
            12,
        );
        let events = uc.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "one state change, one line");
        assert_eq!(events[0].tool_name.as_deref(), Some("ssh_session_create"));
        assert_eq!(events[0].event_type, "state_change");
        assert_eq!(events[0].host, "raspberry");
        assert_eq!(events[0].command, "ssh_session_create session_id=sess-1");
        assert!(
            matches!(
                events[0].result,
                crate::security::CommandResult::StateChanged { duration_ms: 12 }
            ),
            "got {:?}",
            events[0].result
        );
    }

    /// No history entry, and it is deliberate: `HistoryEntry::exit_code` is a
    /// non-optional `u32` whose `0` means success, so recording a state change
    /// there would invent exactly the code `StateChanged` refuses.
    #[test]
    fn a_state_change_adds_nothing_to_the_command_history() {
        let uc = test_use_case();
        assert_eq!(uc.history.len(), 0);
        uc.log_state_change("ssh_config_set", NO_HOST, "ssh_config_set key=k value=1", 0);
        assert_eq!(
            uc.history.len(),
            0,
            "a command history must not gain an entry for something that ran no command"
        );
        assert_eq!(uc.audit_logger.drain_for_test().len(), 1);
    }

    /// The redaction is applied to the OPERATION and not to the HOST, and
    /// the asymmetry is what this pins.
    ///
    /// It replaces a test that asserted `NO_HOST` "survives redaction": since
    /// neither `log_state_change` nor `AuditLogger::log` ever sanitizes
    /// `host`, that could not fail on what it promised. The probe here is a
    /// literal the default `Sanitizer` is known to mask (`AKIA` + 16, pinned
    /// by `sanitizer.rs`'s own tests), placed in BOTH fields of one call: it
    /// must disappear from `command` and remain in `host`. So the test goes
    /// red if the redaction is ever dropped from the operation, and red again
    /// if it is ever extended to the host — which would mangle `<no-host>`
    /// and every real alias with it, and silently break the greps this
    /// convention exists for.
    #[test]
    fn the_operation_is_redacted_and_the_host_is_passed_through_verbatim() {
        let uc = test_use_case();
        let probe = "AKIAIOSFODNN7EXAMPLE";
        uc.log_state_change(
            "ssh_config_set",
            probe,
            &format!("ssh_config_set key={probe} value=80000"),
            0,
        );
        let events = uc.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1);
        assert!(
            !events[0].command.contains(probe),
            "the operation goes through the sanitizer, got {:?}",
            events[0].command
        );
        assert!(
            events[0].command.starts_with("ssh_config_set key="),
            "and only the secret is masked, got {:?}",
            events[0].command
        );
        assert_eq!(
            events[0].host, probe,
            "`host` is passed through verbatim — the field a grep for an \
             alias, or for the {NO_HOST} sentinel, has to be able to match"
        );
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

        let response = use_case.process_success("test_tool", "host", "echo test", &output, &[]);

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

        use_case.log_success("test_tool", "raspberry", "uptime", 0, 12);

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

        let response = use_case.process_success("test_tool", "host", "env", &output, &[]);

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

        let response = use_case.process_success("test_tool", "host", "failing_cmd", &output, &[]);

        assert_eq!(response.exit_code, 1);
        assert!(response.output.contains("Error occurred"));
    }

    #[test]
    fn test_log_denied_does_not_panic() {
        let use_case = create_test_use_case();

        // Should not panic even with disabled logger
        use_case.log_denied("test_tool", "host1", "rm -rf /", "blacklisted");
        use_case.log_denied(
            "test_tool",
            "host2",
            "dangerous_command",
            "not in whitelist",
        );
    }

    #[test]
    fn test_log_failure_does_not_panic() {
        let use_case = create_test_use_case();

        // Should not panic even with disabled logger
        use_case.log_failure("test_tool", "host1", "ls", "connection timeout");
        use_case.log_failure("test_tool", "host2", "pwd", "network error");
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
