//! Command-history secret redaction tests (Task 6, audit 2026-08-13, B5/B6).
//!
//! An AWX bearer token typed on a command line (`-H 'Authorization: Bearer
//! {token}'`, built in `src/domain/use_cases/awx.rs`) was stored verbatim in
//! `CommandHistory` — only the *output* went through the sanitizer, not the
//! command itself. `ssh_history` and the `history://recent` MCP resource then
//! re-exported it in clear text. Modelled on `tests/security_audit_redaction.rs`.

use std::sync::Arc;

use bridge_mcp::config::SecurityConfig;
use bridge_mcp::domain::{CommandHistory, ExecuteCommandUseCase, HistoryConfig};
use bridge_mcp::ports::CommandOutput;
use bridge_mcp::{AuditLogger, CommandValidator, Sanitizer};

fn use_case_with_history() -> (ExecuteCommandUseCase, Arc<CommandHistory>) {
    let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
    let use_case = ExecuteCommandUseCase::new(
        Arc::new(CommandValidator::new(&SecurityConfig::default())),
        Arc::new(Sanitizer::with_defaults()),
        Arc::new(AuditLogger::disabled()),
        Arc::clone(&history),
    );
    (use_case, history)
}

#[test]
fn history_redacts_awx_bearer_token_on_success() {
    let (use_case, history) = use_case_with_history();

    let token = "abc123def456ghi789jkl012mno345";
    let command = format!("curl -H 'Authorization: Bearer {token}' https://awx/api");
    let output = CommandOutput {
        stdout: "ok".to_string(),
        stderr: String::new(),
        exit_code: 0,
        duration_ms: 5,
    };

    let response = use_case.process_success("awx", &command, &output);

    // The response's own `command` field must not leak the token either.
    assert!(
        !response.command.contains(token),
        "bearer token leaked into ExecuteCommandResponse.command: {}",
        response.command
    );

    let recent = history.recent(1);
    assert_eq!(recent.len(), 1);
    assert!(
        !recent[0].command.contains(token),
        "bearer token leaked into CommandHistory entry: {}",
        recent[0].command
    );
}

#[test]
fn history_redacts_awx_bearer_token_on_failure() {
    let (use_case, history) = use_case_with_history();

    let token = "abc123def456ghi789jkl012mno345";
    let command = format!("curl -H 'Authorization: Bearer {token}' https://awx/api");

    use_case.log_failure("awx", &command, "connection timeout");

    let recent = history.recent(1);
    assert_eq!(recent.len(), 1);
    assert!(
        !recent[0].command.contains(token),
        "bearer token leaked into CommandHistory entry (failure path): {}",
        recent[0].command
    );
}

/// Guard: a benign command with nothing sanitizer-worthy in it must round-trip
/// byte-identical through history — the fix must not mangle ordinary commands.
#[test]
fn history_benign_command_round_trips_byte_identical() {
    let (use_case, history) = use_case_with_history();

    let output = CommandOutput {
        stdout: "file1.txt\nfile2.txt\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
        duration_ms: 12,
    };

    let response = use_case.process_success("host1", "ls -la", &output);
    assert_eq!(response.command, "ls -la");

    let recent = history.recent(1);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].command, "ls -la");
}
