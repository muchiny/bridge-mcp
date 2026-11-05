//! Cron Command Builder
//!
//! Builds cron job management CLI commands for remote execution via SSH.
//! Supports listing, adding, and removing cron jobs.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a cron schedule has the expected format (5 fields).
/// Each field is separated by whitespace. Accepts standard cron syntax:
/// minute hour day-of-month month day-of-week
pub fn validate_cron_schedule(schedule: &str) -> Result<()> {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid cron schedule: expected 5 fields (minute hour day month weekday), got {}",
                fields.len()
            ),
        });
    }
    // Each field should only contain: digits, *, /, -, comma. None starts
    // with `-`: cronie reads a line that starts with one as "do not log this
    // job", and no valid field does.
    for (i, field) in fields.iter().enumerate() {
        if field.starts_with('-')
            || !field
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '*' | '/' | '-' | ','))
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid cron field {}: '{}' contains invalid characters",
                    i + 1,
                    field
                ),
            });
        }
    }
    Ok(())
}

/// Validate that a cron comment does not contain newlines.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the comment contains newline characters.
pub fn validate_cron_comment(comment: &str) -> Result<()> {
    if comment.contains('\n') || comment.contains('\r') {
        return Err(BridgeError::CommandDenied {
            reason: "Cron comment must not contain newlines".to_string(),
        });
    }
    Ok(())
}

/// Validate that text going into a crontab line is a single line.
///
/// A crontab is parsed line by line: a newline in the command would start a
/// second entry that no validator looked at.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] naming `what` if `text` contains a
/// line feed or a carriage return.
fn validate_single_line(what: &str, text: &str) -> Result<()> {
    if text.contains(['\n', '\r']) {
        return Err(BridgeError::CommandDenied {
            reason: format!("Cron {what} must not contain newlines"),
        });
    }
    Ok(())
}

/// `command` with every `%` that cron would not read as escaped written
/// `\%`, which cron hands to the shell as a plain `%`. Cron reads a backslash
/// as escaping the next character, so in `\\%` the `%` is not escaped; this
/// follows the same rule.
fn escape_cron_percent(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut escaped = false;
    for c in command.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '%' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Builds cron management commands for remote execution.
pub struct CronCommandBuilder;

impl CronCommandBuilder {
    /// Build a command to list cron jobs.
    ///
    /// Constructs: `crontab -l [-u {user}]` and optionally reads `/etc/cron.d/`
    #[must_use]
    pub fn build_list_command(user: Option<&str>, system: bool) -> String {
        let mut cmd = String::from("crontab -l");

        if let Some(u) = user {
            cmd = format!("crontab -l -u {}", shell_escape(u));
        }

        if system {
            let _ = write!(
                cmd,
                " 2>/dev/null; echo '--- /etc/cron.d/ ---'; ls -la /etc/cron.d/ 2>/dev/null; \
                 echo '--- /etc/crontab ---'; cat /etc/crontab 2>/dev/null"
            );
        }

        cmd
    }

    /// Build a command to add a cron job.
    ///
    /// Constructs: `(crontab -l 2>/dev/null; printf '%s\n' "{schedule} {command}") | crontab -`
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the schedule, command or
    /// comment is invalid or spans more than one line.
    pub fn build_add_command(
        schedule: &str,
        command: &str,
        user: Option<&str>,
        comment: Option<&str>,
    ) -> Result<String> {
        validate_single_line("schedule", schedule)?;
        validate_cron_schedule(schedule)?;
        validate_single_line("command", command)?;
        if let Some(c) = comment {
            validate_cron_comment(c)?;
        }

        let mut cron_line = String::new();

        if let Some(c) = comment {
            let _ = writeln!(cron_line, "# {c}");
        }

        // cron ends the command at an unescaped `%` and feeds the rest to it
        // as stdin, so the job would not be the command the caller (and the
        // whitelist) saw. Escaped, every `%` reaches the shell as written.
        let _ = write!(cron_line, "{schedule} {}", escape_cron_percent(command));

        let crontab_cmd = if let Some(u) = user {
            format!("crontab -u {} -l", shell_escape(u))
        } else {
            String::from("crontab -l")
        };

        let set_cmd = if let Some(u) = user {
            format!("crontab -u {} -", shell_escape(u))
        } else {
            String::from("crontab -")
        };

        Ok(format!(
            "({crontab_cmd} 2>/dev/null; printf '%s\\n' {}) | {set_cmd}",
            shell_escape(&cron_line)
        ))
    }

    /// Build a command to remove a cron job by pattern.
    ///
    /// Removes every line that contains `pattern` as a literal string
    /// (`grep -F -v -e`). The filtered crontab is installed only when `crontab
    /// -l` and `grep` both ran: an empty pipe stage used to install an empty
    /// crontab when `grep` failed.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `pattern` is empty or spans
    /// more than one line (a second, empty pattern would match every line).
    pub fn build_remove_command(pattern: &str, user: Option<&str>) -> Result<String> {
        if pattern.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Cron pattern must not be empty: it would remove every entry".to_string(),
            });
        }
        validate_single_line("pattern", pattern)?;
        let crontab_cmd = if let Some(u) = user {
            format!("crontab -u {} -l", shell_escape(u))
        } else {
            String::from("crontab -l")
        };

        let set_cmd = if let Some(u) = user {
            format!("crontab -u {} -", shell_escape(u))
        } else {
            String::from("crontab -")
        };

        Ok(format!(
            "if cur=$({crontab_cmd}); then \
             new=$(printf '%s\\n' \"$cur\" | grep -F -v -e {}); rc=$?; \
             if [ \"$rc\" -le 1 ]; then printf '%s\\n' \"$new\" | {set_cmd}; \
             else echo 'cron remove aborted: grep failed' >&2; exit \"$rc\"; fi; \
             else echo 'cron remove aborted: crontab -l failed' >&2; exit 1; fi",
            shell_escape(pattern)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_starting_with_a_dash_is_refused() {
        assert!(validate_cron_schedule("-0 * * * *").is_err());
        assert!(validate_cron_schedule("0 * * * -1").is_err());
        assert!(validate_cron_schedule("0-30/5 * * * 1-5").is_ok());
    }

    #[test]
    fn test_list_default() {
        let cmd = CronCommandBuilder::build_list_command(None, false);
        assert_eq!(cmd, "crontab -l");
    }

    #[test]
    fn test_list_with_user() {
        let cmd = CronCommandBuilder::build_list_command(Some("www-data"), false);
        assert!(cmd.contains("-u 'www-data'"));
    }

    #[test]
    fn test_list_system() {
        let cmd = CronCommandBuilder::build_list_command(None, true);
        assert!(cmd.contains("/etc/cron.d/"));
        assert!(cmd.contains("/etc/crontab"));
    }

    #[test]
    fn test_add_simple() {
        let cmd =
            CronCommandBuilder::build_add_command("0 * * * *", "/usr/bin/backup.sh", None, None)
                .unwrap();
        assert!(cmd.contains("crontab -l"));
        assert!(cmd.contains("0 * * * * /usr/bin/backup.sh"));
        assert!(cmd.contains("crontab -"));
    }

    #[test]
    fn test_add_with_user() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 2 * * *",
            "/opt/cleanup.sh",
            Some("root"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("-u 'root'"));
    }

    #[test]
    fn test_add_with_comment() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 3 * * *",
            "/opt/backup.sh",
            None,
            Some("Daily backup"),
        )
        .unwrap();
        assert!(cmd.contains("# Daily backup"));
    }

    #[test]
    fn test_add_comment_produces_real_newline() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 3 * * *",
            "/opt/backup.sh",
            None,
            Some("Daily backup"),
        )
        .unwrap();
        // Comment and schedule must be on separate lines (real newline, not literal \n)
        assert!(!cmd.contains("backup\\n"), "{cmd}");
        assert!(cmd.contains("# Daily backup\n0 3"));
    }

    #[test]
    fn test_remove_refuses_patterns_that_match_every_line() {
        for bad in ["", "x\n", "\n", "a\r"] {
            let err = CronCommandBuilder::build_remove_command(bad, None).unwrap_err();
            assert!(err.to_string().contains("Cron pattern"), "{err}");
        }
    }

    #[test]
    fn test_remove_installs_only_after_crontab_and_grep_ran() {
        let cmd = CronCommandBuilder::build_remove_command("--bogus", Some("bob")).unwrap();
        assert!(cmd.contains("grep -F -v -e '--bogus'"), "{cmd}");
        assert!(
            cmd.starts_with("if cur=$(crontab -u 'bob' -l); then"),
            "{cmd}"
        );
        assert!(cmd.contains("if [ \"$rc\" -le 1 ]; then"), "{cmd}");
        assert!(cmd.contains("| crontab -u 'bob' -;"), "{cmd}");
        assert!(cmd.contains("exit \"$rc\""), "{cmd}");
    }

    #[test]
    fn test_add_refuses_a_command_that_spans_lines() {
        for bad in ["a\n* * * * * evil", "a\r", "\n"] {
            let err =
                CronCommandBuilder::build_add_command("0 * * * *", bad, None, None).unwrap_err();
            assert!(err.to_string().contains("Cron command"), "{err}");
        }
        let err =
            CronCommandBuilder::build_add_command("0 * * *\n* *", "x", None, None).unwrap_err();
        assert!(err.to_string().contains("Cron schedule"), "{err}");
    }

    #[test]
    fn test_add_escapes_percent_for_cron() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 * * * *",
            r"mysql -D app %system id%x date +\%F",
            None,
            None,
        )
        .unwrap();
        assert!(
            cmd.contains(r"mysql -D app \%system id\%x date +\%F"),
            "{cmd}"
        );
        // Two backslashes escape each other, so the `%` after them is bare.
        assert_eq!(escape_cron_percent(r"a\\%b"), r"a\\\%b");
        assert_eq!(escape_cron_percent(r"a\\\%b"), r"a\\\%b");
        assert_eq!(escape_cron_percent("100%"), r"100\%");
    }

    #[test]
    fn test_add_prints_the_line_with_a_format() {
        let cmd =
            CronCommandBuilder::build_add_command("0 * * * *", "-n echo", None, None).unwrap();
        assert!(cmd.contains("printf '%s\\n' '0 * * * * -n echo'"), "{cmd}");
        assert!(!cmd.contains("echo '"), "{cmd}");
    }

    #[test]
    fn test_remove() {
        let cmd = CronCommandBuilder::build_remove_command("backup.sh", None).unwrap();
        assert!(cmd.contains("grep -F -v -e 'backup.sh'"));
        assert!(cmd.contains("crontab -"));
    }

    #[test]
    fn test_remove_with_user() {
        let cmd = CronCommandBuilder::build_remove_command("cleanup", Some("root")).unwrap();
        assert!(cmd.contains("-u 'root'"));
        assert!(cmd.contains("grep -F -v -e 'cleanup'"));
    }

    // ── validate_cron_schedule ─────────────────────────────────────

    #[test]
    fn test_validate_cron_valid() {
        assert!(validate_cron_schedule("0 * * * *").is_ok());
        assert!(validate_cron_schedule("0 2 * * *").is_ok());
        assert!(validate_cron_schedule("*/5 * * * *").is_ok());
        assert!(validate_cron_schedule("0 0 1 1 *").is_ok());
        assert!(validate_cron_schedule("0,30 * * * *").is_ok());
        assert!(validate_cron_schedule("0 9-17 * * 1-5").is_ok());
    }

    #[test]
    fn test_validate_cron_invalid_field_count() {
        assert!(validate_cron_schedule("* * *").is_err());
        assert!(validate_cron_schedule("* * * * * *").is_err());
        assert!(validate_cron_schedule("*").is_err());
        assert!(validate_cron_schedule("").is_err());
    }

    #[test]
    fn test_validate_cron_invalid_chars() {
        assert!(validate_cron_schedule("0 * * * ; rm -rf /").is_err());
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_add_injection_in_command() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 * * * *",
            "/opt/backup.sh; rm -rf /",
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("'0 * * * * /opt/backup.sh; rm -rf /'"));
    }

    #[test]
    fn test_add_injection_in_user() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 * * * *",
            "/opt/job.sh",
            Some("root; cat /etc/shadow"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("-u 'root; cat /etc/shadow'"));
    }

    #[test]
    fn test_remove_injection_in_pattern() {
        let cmd = CronCommandBuilder::build_remove_command("backup.sh; rm -rf /", None).unwrap();
        assert!(cmd.contains("grep -F -v -e 'backup.sh; rm -rf /'"));
    }

    #[test]
    fn test_list_injection_in_user() {
        let cmd = CronCommandBuilder::build_list_command(Some("$(whoami)"), false);
        assert!(cmd.contains("-u '$(whoami)'"));
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_add_all_options() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 2 * * *",
            "/opt/backup.sh",
            Some("backupuser"),
            Some("Nightly backup"),
        )
        .unwrap();
        assert!(cmd.contains("-u 'backupuser'"));
        assert!(cmd.contains("# Nightly backup"));
        assert!(cmd.contains("0 2 * * * /opt/backup.sh"));
    }

    #[test]
    fn test_list_user_and_system() {
        let cmd = CronCommandBuilder::build_list_command(Some("www-data"), true);
        assert!(cmd.contains("-u 'www-data'"));
        assert!(cmd.contains("/etc/cron.d/"));
        assert!(cmd.contains("/etc/crontab"));
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_add_command_with_single_quotes() {
        let cmd =
            CronCommandBuilder::build_add_command("0 * * * *", "echo 'hello world'", None, None)
                .unwrap();
        // The whole cron_line is shell-escaped, so internal quotes get escaped
        assert!(cmd.contains("hello"));
    }

    #[test]
    fn test_remove_pattern_with_special_chars() {
        let cmd = CronCommandBuilder::build_remove_command("backup.*\\.sh", None).unwrap();
        assert!(cmd.contains("grep -F -v -e 'backup.*\\.sh'"));
    }

    #[test]
    fn test_add_long_command() {
        let long_cmd = "x".repeat(500);
        let cmd =
            CronCommandBuilder::build_add_command("0 * * * *", &long_cmd, None, None).unwrap();
        assert!(cmd.contains(&long_cmd));
    }

    // ============== validate_cron_comment ==============

    #[test]
    fn test_validate_cron_comment_valid() {
        assert!(validate_cron_comment("Daily backup").is_ok());
        assert!(validate_cron_comment("Run at midnight").is_ok());
    }

    #[test]
    fn test_validate_cron_comment_newline_rejected() {
        assert!(validate_cron_comment("line1\nline2").is_err());
        assert!(validate_cron_comment("line1\rline2").is_err());
    }

    #[test]
    fn test_add_invalid_schedule_rejected() {
        let result = CronCommandBuilder::build_add_command("bad", "/bin/test", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_invalid_comment_rejected() {
        let result = CronCommandBuilder::build_add_command(
            "0 * * * *",
            "/bin/test",
            None,
            Some("line1\nline2"),
        );
        assert!(result.is_err());
    }

    // ============== validate_cron_schedule Additional Tests ==============

    #[test]
    fn test_validate_cron_step_and_range() {
        assert!(validate_cron_schedule("*/15 0-23 * * *").is_ok());
    }

    #[test]
    fn test_validate_cron_injection_in_field() {
        assert!(validate_cron_schedule("0 * * * $(rm -rf /)").is_err());
    }

    #[test]
    fn test_validate_cron_semicolon_in_field() {
        assert!(validate_cron_schedule("0 * * * ;").is_err());
    }

    #[test]
    fn test_validate_cron_letters_rejected() {
        assert!(validate_cron_schedule("0 0 * jan *").is_err());
        assert!(validate_cron_schedule("0 0 * * mon").is_err());
    }

    #[test]
    fn test_validate_cron_pipe_rejected() {
        assert!(validate_cron_schedule("0 * * | *").is_err());
    }

    #[test]
    fn test_validate_cron_extra_whitespace() {
        // split_whitespace handles leading/trailing whitespace
        assert!(validate_cron_schedule("  0 * * * *  ").is_ok());
    }

    #[test]
    fn test_validate_cron_error_message_field_count() {
        let result = validate_cron_schedule("* * *");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("got 3"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_cron_error_message_invalid_char() {
        let result = validate_cron_schedule("0 * * * abc");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("field 5"));
                assert!(reason.contains("abc"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }
}
