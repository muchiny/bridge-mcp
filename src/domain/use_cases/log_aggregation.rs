//! Log Aggregation Command Builder
//!
//! Builds log search, aggregation, and tail commands for multi-host
//! log analysis via SSH.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

const DEFAULT_LOG_FILES: &str = "/var/log/syslog /var/log/messages /var/log/auth.log";
const MAX_TAIL_LINES: u64 = 5000;

/// Validate a grep pattern for safety.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the pattern is empty or contains
/// newline characters.
pub fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Search pattern must not be empty".to_string(),
        });
    }
    if pattern.contains('\n') || pattern.contains('\r') {
        return Err(BridgeError::CommandDenied {
            reason: "Search pattern must not contain newlines".to_string(),
        });
    }
    if pattern.len() > 1000 {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Search pattern too long: {} chars (max 1000)",
                pattern.len()
            ),
        });
    }
    Ok(())
}

/// Maximum accepted length of the whole `log_files` argument.
const MAX_LOG_FILES_LEN: usize = 4096;
/// Maximum number of whitespace-separated paths in `log_files`.
const MAX_LOG_FILES_COUNT: usize = 64;

/// Characters allowed in a `log_files` argument, on top of ASCII alphanumerics.
///
/// `*`, `?`, `[` and `]` are kept so glob patterns still expand — the argument
/// is deliberately interpolated *unquoted* as several shell words. Everything
/// that could start a command (`$`, `` ` ``, `;`, `&`, `|`, `<`, `>`, `(`, `)`,
/// `\`, quotes, braces, tilde, newline) is absent from this set.
const LOG_FILES_ALLOWED_PUNCT: &[char] = &[
    '.', '_', '-', '/', '*', '?', '[', ']', ':', '+', '@', ',', '=', '%',
];

/// Validate the `log_files` argument.
///
/// `log_files` is a whitespace-separated list of paths that the log builders
/// interpolate as *multiple* shell words, so it cannot be wrapped in a single
/// [`shell_escape`] call without destroying that meaning. It is validated
/// against a strict character allowlist instead: globbing keeps working while
/// command substitution and command chaining become unrepresentable.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the list is empty, too long, holds
/// too many entries, or contains any character outside the allowlist.
pub fn validate_log_files(log_files: &str) -> Result<()> {
    if log_files.trim().is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "log_files must not be empty".to_string(),
        });
    }
    if log_files.len() > MAX_LOG_FILES_LEN {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "log_files too long: {} chars (max {MAX_LOG_FILES_LEN})",
                log_files.len()
            ),
        });
    }
    if let Some(bad) = log_files
        .chars()
        .find(|c| *c != ' ' && !c.is_ascii_alphanumeric() && !LOG_FILES_ALLOWED_PUNCT.contains(c))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("log_files contains a disallowed character: {bad:?}"),
        });
    }
    let count = log_files.split_whitespace().count();
    if count > MAX_LOG_FILES_COUNT {
        return Err(BridgeError::CommandDenied {
            reason: format!("log_files lists {count} paths (max {MAX_LOG_FILES_COUNT})"),
        });
    }
    Ok(())
}

/// Validate the number of tail lines.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the line count exceeds the maximum.
pub fn validate_lines(lines: u64) -> Result<()> {
    if lines == 0 {
        return Err(BridgeError::CommandDenied {
            reason: "Line count must be at least 1".to_string(),
        });
    }
    if lines > MAX_TAIL_LINES {
        return Err(BridgeError::CommandDenied {
            reason: format!("Line count {lines} exceeds maximum of {MAX_TAIL_LINES}"),
        });
    }
    Ok(())
}

/// Builds log aggregation commands for remote execution.
pub struct LogAggregationCommandBuilder;

impl LogAggregationCommandBuilder {
    /// Build a command to search logs for a pattern.
    ///
    /// Uses `journalctl --grep` when available, falling back to `grep -r`.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is invalid.
    pub fn build_log_search_command(
        pattern: &str,
        log_files: Option<&str>,
        since: Option<&str>,
    ) -> Result<String> {
        validate_pattern(pattern)?;

        let files = log_files.unwrap_or(DEFAULT_LOG_FILES);
        validate_log_files(files)?;
        let escaped_pattern = shell_escape(pattern);

        let mut journal_cmd = format!("journalctl --no-pager -q --grep {escaped_pattern}");
        if let Some(since_val) = since {
            journal_cmd = format!("{journal_cmd} --since {}", shell_escape(since_val));
        }

        Ok(format!(
            "{journal_cmd} 2>/dev/null || grep -r {escaped_pattern} {files} 2>/dev/null | tail -100"
        ))
    }

    /// Build a command to aggregate log statistics.
    ///
    /// Counts total lines, error lines, and warning lines across log files.
    ///
    /// # Errors
    ///
    /// Returns an error if `log_files` fails [`validate_log_files`].
    pub fn build_log_aggregate_command(log_files: Option<&str>) -> Result<String> {
        let files = log_files.unwrap_or(DEFAULT_LOG_FILES);
        validate_log_files(files)?;
        Ok(format!(
            "printf 'FILE\\tTOTAL\\tERRORS\\tWARNINGS\\n' && \
             for f in {files}; do \
               if [ -f \"$f\" ]; then \
                 total=$(wc -l < \"$f\" 2>/dev/null || echo 0); \
                 errors=$(grep -ci 'error' \"$f\" 2>/dev/null || echo 0); \
                 warnings=$(grep -ci 'warn' \"$f\" 2>/dev/null || echo 0); \
                 printf '%s\\t%s\\t%s\\t%s\\n' \"$f\" \"$total\" \"$errors\" \"$warnings\"; \
               fi; \
             done"
        ))
    }

    /// Build a command to tail log files.
    ///
    /// # Errors
    ///
    /// Returns an error if the line count is invalid.
    pub fn build_log_tail_command(log_files: Option<&str>, lines: Option<u64>) -> Result<String> {
        let n = lines.unwrap_or(50);
        validate_lines(n)?;

        let files = log_files.unwrap_or(DEFAULT_LOG_FILES);
        validate_log_files(files)?;
        Ok(format!("tail -n {n} {files} 2>/dev/null"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_pattern ─────────────────────────────────────

    #[test]
    fn test_validate_pattern_valid() {
        assert!(validate_pattern("error").is_ok());
        assert!(validate_pattern("ERROR|WARN").is_ok());
        assert!(validate_pattern("connection refused").is_ok());
    }

    #[test]
    fn test_validate_pattern_empty() {
        let err = validate_pattern("").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_pattern_newline() {
        assert!(validate_pattern("line1\nline2").is_err());
        assert!(validate_pattern("line1\rline2").is_err());
    }

    #[test]
    fn test_validate_pattern_too_long() {
        let long = "x".repeat(1001);
        let err = validate_pattern(&long).unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("too long"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_pattern_max_length_ok() {
        let exact = "x".repeat(1000);
        assert!(validate_pattern(&exact).is_ok());
    }

    // ── validate_lines ───────────────────────────────────────

    #[test]
    fn test_validate_lines_valid() {
        assert!(validate_lines(1).is_ok());
        assert!(validate_lines(100).is_ok());
        assert!(validate_lines(5000).is_ok());
    }

    #[test]
    fn test_validate_lines_zero() {
        assert!(validate_lines(0).is_err());
    }

    #[test]
    fn test_validate_lines_exceeds_max() {
        let err = validate_lines(5001).unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("5001"));
                assert!(reason.contains("5000"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── build_log_search_command ─────────────────────────────

    #[test]
    fn test_search_defaults() {
        let cmd =
            LogAggregationCommandBuilder::build_log_search_command("error", None, None).unwrap();
        assert!(cmd.contains("journalctl"));
        assert!(cmd.contains("--grep 'error'"));
        assert!(cmd.contains("grep -r 'error'"));
        assert!(cmd.contains(DEFAULT_LOG_FILES));
        assert!(cmd.contains("tail -100"));
    }

    #[test]
    fn test_search_with_custom_files() {
        let cmd = LogAggregationCommandBuilder::build_log_search_command(
            "warn",
            Some("/var/log/app.log"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("/var/log/app.log"));
        assert!(!cmd.contains(DEFAULT_LOG_FILES));
    }

    #[test]
    fn test_search_with_since() {
        let cmd = LogAggregationCommandBuilder::build_log_search_command(
            "error",
            None,
            Some("1 hour ago"),
        )
        .unwrap();
        assert!(cmd.contains("--since '1 hour ago'"));
    }

    #[test]
    fn test_search_invalid_pattern() {
        let result = LogAggregationCommandBuilder::build_log_search_command("", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_shell_injection() {
        let cmd = LogAggregationCommandBuilder::build_log_search_command(
            "'; rm -rf /; echo '",
            None,
            None,
        )
        .unwrap();
        // Pattern should be safely escaped
        assert!(cmd.contains("'\\''"));
    }

    // ── build_log_aggregate_command ──────────────────────────

    #[test]
    fn test_aggregate_defaults() {
        let cmd = LogAggregationCommandBuilder::build_log_aggregate_command(None).unwrap();
        assert!(cmd.contains("FILE"));
        assert!(cmd.contains("TOTAL"));
        assert!(cmd.contains("wc -l"));
        assert!(cmd.contains("error"));
        assert!(cmd.contains("warn"));
        assert!(cmd.contains(DEFAULT_LOG_FILES));
    }

    #[test]
    fn test_aggregate_custom_files() {
        let cmd = LogAggregationCommandBuilder::build_log_aggregate_command(Some(
            "/var/log/nginx/access.log",
        ))
        .unwrap();
        assert!(cmd.contains("/var/log/nginx/access.log"));
    }

    // ── build_log_tail_command ───────────────────────────────

    #[test]
    fn test_tail_defaults() {
        let cmd = LogAggregationCommandBuilder::build_log_tail_command(None, None).unwrap();
        assert!(cmd.contains("tail -n 50"));
        assert!(cmd.contains(DEFAULT_LOG_FILES));
    }

    #[test]
    fn test_tail_custom_lines() {
        let cmd = LogAggregationCommandBuilder::build_log_tail_command(None, Some(200)).unwrap();
        assert!(cmd.contains("tail -n 200"));
    }

    #[test]
    fn test_tail_custom_files() {
        let cmd =
            LogAggregationCommandBuilder::build_log_tail_command(Some("/var/log/app.log"), None)
                .unwrap();
        assert!(cmd.contains("/var/log/app.log"));
    }

    #[test]
    fn test_tail_invalid_lines() {
        let result = LogAggregationCommandBuilder::build_log_tail_command(None, Some(6000));
        assert!(result.is_err());
    }

    #[test]
    fn test_tail_zero_lines() {
        let result = LogAggregationCommandBuilder::build_log_tail_command(None, Some(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_tail_max_lines() {
        let cmd = LogAggregationCommandBuilder::build_log_tail_command(None, Some(5000)).unwrap();
        assert!(cmd.contains("tail -n 5000"));
    }

    // ── validate_log_files (AUDIT-2026-08 B1) ────────────────
    //
    // `log_files` is interpolated as *multiple* shell words, so it cannot be
    // wrapped in a single `shell_escape`. It is validated against a strict
    // character allowlist instead, which keeps globbing usable while making
    // command substitution and command chaining unrepresentable.

    #[test]
    fn test_validate_log_files_accepts_plain_paths() {
        assert!(validate_log_files("/var/log/syslog /var/log/auth.log").is_ok());
    }

    #[test]
    fn test_validate_log_files_accepts_globs() {
        assert!(validate_log_files("/var/log/nginx/*.log").is_ok());
        assert!(validate_log_files("/var/log/pods/*/*.log").is_ok());
        assert!(validate_log_files("/var/log/app-[0-9].log").is_ok());
    }

    #[test]
    fn test_validate_log_files_rejects_command_substitution() {
        assert!(validate_log_files("/var/log/syslog $(id > /tmp/pwn)").is_err());
        assert!(validate_log_files("/var/log/`id`").is_err());
        assert!(validate_log_files("/var/log/${IFS}x").is_err());
    }

    #[test]
    fn test_validate_log_files_rejects_command_chaining() {
        for evil in [
            "/var/log/syslog; id",
            "/var/log/syslog && id",
            "/var/log/syslog | id",
            "/var/log/syslog > /etc/passwd",
            "/var/log/syslog\nid",
        ] {
            assert!(
                validate_log_files(evil).is_err(),
                "must reject log_files {evil:?}"
            );
        }
    }

    #[test]
    fn test_validate_log_files_rejects_empty() {
        assert!(validate_log_files("").is_err());
        assert!(validate_log_files("   ").is_err());
    }

    #[test]
    fn test_log_tail_rejects_injected_log_files() {
        let result = LogAggregationCommandBuilder::build_log_tail_command(
            Some("/var/log/syslog $(id > /tmp/pwn)"),
            Some(10),
        );
        assert!(result.is_err(), "ssh_log_tail_multi must not build RCE");
    }

    #[test]
    fn test_log_search_rejects_injected_log_files() {
        let result = LogAggregationCommandBuilder::build_log_search_command(
            "error",
            Some("/var/log/syslog; id"),
            None,
        );
        assert!(result.is_err(), "ssh_log_search_multi must not build RCE");
    }

    #[test]
    fn test_log_aggregate_rejects_injected_log_files() {
        let result =
            LogAggregationCommandBuilder::build_log_aggregate_command(Some("/var/log/`id`"));
        assert!(result.is_err(), "ssh_log_aggregate must not build RCE");
    }

    #[test]
    fn test_log_aggregate_accepts_valid_files() {
        let cmd = LogAggregationCommandBuilder::build_log_aggregate_command(Some("/var/log/a.log"))
            .unwrap();
        assert!(cmd.contains("for f in /var/log/a.log"));
    }
}
