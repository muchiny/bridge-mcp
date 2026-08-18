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
    // Nor must the formatted `output` field, which embeds "Command: {command}"
    // — `format_output` must receive the already-redacted command, not rely
    // solely on the outer `sanitize(&result)` pass to catch it a second time.
    assert!(
        !response.output.contains(token),
        "bearer token leaked into ExecuteCommandResponse.output: {}",
        response.output
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

/// Pins the behaviour change documented in CHANGELOG.md under `## [Unreleased]`
/// -> `### Security`: `Sanitizer::with_defaults()` / `SanitizeConfig::default()`
/// has `entropy_detection: true` (threshold 4.5, min length 16), and commands
/// now go through the same sanitizer as output. An opaque, high-entropy
/// argument 16+ characters long — not a recognized secret pattern, no
/// "password"/"token"/"secret"/"key"/"bearer" keyword anywhere in the command
/// — must still be redacted purely by the entropy detector. This is NOT a
/// vulnerability; it is the documented, intentional trade-off. If this test
/// starts failing, the CHANGELOG entry is now false and must be corrected
/// (not the other way around).
#[test]
fn history_entropy_detection_redacts_opaque_high_entropy_argument() {
    let (use_case, history) = use_case_with_history();

    // High-entropy, 30-char opaque argument (mixed-case alphanumeric), well
    // over the default min_length of 16 — same shape used by
    // `EntropyDetector`'s own unit tests (src/security/entropy.rs).
    let opaque_arg = "a8Kz9xQ2m4Fp7Lw1Bn3Yd5Rj6Gt0Hv";
    let command = format!("deploy-cli push --build {opaque_arg} --env staging");
    let output = CommandOutput {
        stdout: "deployed".to_string(),
        stderr: String::new(),
        exit_code: 0,
        duration_ms: 8,
    };

    let response = use_case.process_success("host1", &command, &output);

    assert!(
        !response.command.contains(opaque_arg),
        "expected the opaque high-entropy argument to be redacted from \
         ExecuteCommandResponse.command per the documented entropy-detection \
         side effect, but it survived: {}",
        response.command
    );

    let recent = history.recent(1);
    assert_eq!(recent.len(), 1);
    assert!(
        !recent[0].command.contains(opaque_arg),
        "expected the opaque high-entropy argument to be redacted from the \
         CommandHistory entry per the documented entropy-detection side \
         effect, but it survived: {}",
        recent[0].command
    );
}
