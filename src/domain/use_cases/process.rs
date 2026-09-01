//! Process Command Builder
//!
//! Builds process management CLI commands for remote execution via SSH.
//! Supports process listing, killing, and resource usage snapshots.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds process management commands for remote execution.
pub struct ProcessCommandBuilder;

impl ProcessCommandBuilder {
    /// Build a `ps` command to list processes.
    ///
    /// Constructs: `ps aux [--sort=-{field}]` with optional user/grep filtering.
    ///
    /// When `filter` is set, the pipeline preserves the `ps` header line so
    /// downstream columnar parsing (and `columns=[...]` selection) keeps
    /// working. `awk` matches the header by line number (`NR==1`) plus rows
    /// matching the user pattern, while excluding the awk/grep self-process.
    #[must_use]
    pub fn build_list_command(
        user: Option<&str>,
        sort_by: Option<&str>,
        filter: Option<&str>,
    ) -> String {
        let mut cmd = String::from("ps aux");

        if let Some(s) = sort_by {
            let _ = write!(cmd, " --sort=-{}", shell_escape(s));
        }

        if let Some(u) = user {
            cmd = format!(
                "ps -u {} -o pid,ppid,%cpu,%mem,vsz,rss,tty,stat,start,time,command",
                shell_escape(u)
            );
            if let Some(s) = sort_by {
                let _ = write!(cmd, " --sort=-{}", shell_escape(s));
            }
        }

        if let Some(f) = filter {
            let lower = f.to_lowercase();
            let escaped_pattern = shell_escape(&lower);
            // awk -v passes the pattern as a variable, avoiding regex injection
            // and quote-escaping pitfalls. `tolower($0)` makes the match
            // case-insensitive without needing portable IGNORECASE flags.
            let _ = write!(
                cmd,
                " | awk -v p={escaped_pattern} 'NR==1 {{print; next}} index(tolower($0), p) > 0 && !/awk -v p=/ && !/grep -v/ {{print}}'"
            );
        }

        cmd
    }

    /// Build a `kill` command.
    ///
    /// Constructs: `kill -{signal} {pid}`
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the PID is invalid (0 or 1).
    pub fn build_kill_command(pid: u32, signal: Option<&str>) -> Result<String> {
        // Safety: never kill PID 0 (all processes in group) or PID 1 (init/systemd)
        if pid == 0 || pid == 1 {
            return Err(BridgeError::CommandDenied {
                reason: format!("Cannot kill PID {pid}: protected process"),
            });
        }

        let sig = signal.unwrap_or("TERM");
        Self::validate_signal(sig)?;
        Ok(format!("kill -{sig} {pid}"))
    }

    /// Validate a signal name.
    ///
    /// Only allows common signals.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the signal is not allowed.
    pub fn validate_signal(signal: &str) -> Result<()> {
        const ALLOWED: &[&str] = &[
            "TERM", "KILL", "HUP", "INT", "QUIT", "USR1", "USR2", "STOP", "CONT", "15", "9", "1",
            "2", "3", "10", "12", "19", "18",
        ];
        if ALLOWED.contains(&signal) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Signal '{}' is not allowed. Allowed signals: {}",
                    signal,
                    ALLOWED.join(", ")
                ),
            })
        }
    }

    /// Build a top-like snapshot command.
    ///
    /// Constructs: `ps aux --sort=-{field} | head -n {count+1}`
    #[must_use]
    pub fn build_top_command(
        sort_by: Option<&str>,
        user: Option<&str>,
        count: Option<u32>,
    ) -> String {
        let sort = sort_by.unwrap_or("%cpu");
        // Capped, not just wrapped. `+ 1` on `Some(u32::MAX)` panics in
        // debug and wraps to 0 in release — where `overflow-checks` is off —
        // so a caller asking for every process got `head -n 0` and no output
        // at all, which reads as "no processes" rather than as a bad request.
        // The ceiling is well past any real process table; the floor stays at
        // zero, where `head -n 1` prints the header and nothing else.
        let n = count.unwrap_or(20).min(100_000) + 1; // +1 for header

        let mut cmd = String::from("ps aux");

        if let Some(u) = user {
            cmd = format!(
                "ps -u {} -o pid,ppid,%cpu,%mem,vsz,rss,tty,stat,start,time,command",
                shell_escape(u)
            );
        }

        let _ = write!(cmd, " --sort=-{}", shell_escape(sort));
        let _ = write!(cmd, " | head -n {n}");
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `+ 1` on `u32::MAX` wrapped to 0 in release, and `head -n 0` prints
    /// nothing — a silent empty answer to a valid-looking request.
    #[test]
    fn an_enormous_count_does_not_ask_for_zero_rows() {
        for count in [u32::MAX, u32::MAX - 1, 1_000_000] {
            let cmd = ProcessCommandBuilder::build_top_command(None, None, Some(count));
            assert!(
                !cmd.contains("head -n 0"),
                "count {count} must not collapse to an empty listing: {cmd}"
            );
        }
        // And zero rows asked for is still one row of header, not none.
        let cmd = ProcessCommandBuilder::build_top_command(None, None, Some(0));
        assert!(!cmd.contains("head -n 0"), "got: {cmd}");
    }

    #[test]
    fn an_ordinary_count_is_untouched() {
        let cmd = ProcessCommandBuilder::build_top_command(None, None, Some(20));
        assert!(cmd.contains("head -n 21"), "got: {cmd}");
    }

    // ── build_list_command ──────────────────────────────────────────

    #[test]
    fn test_list_default() {
        let cmd = ProcessCommandBuilder::build_list_command(None, None, None);
        assert_eq!(cmd, "ps aux");
    }

    #[test]
    fn test_list_sorted() {
        let cmd = ProcessCommandBuilder::build_list_command(None, Some("%mem"), None);
        assert!(cmd.contains("--sort=-'%mem'"));
    }

    #[test]
    fn test_list_with_user() {
        let cmd = ProcessCommandBuilder::build_list_command(Some("root"), None, None);
        assert!(cmd.contains("-u 'root'"));
    }

    #[test]
    fn test_list_with_filter() {
        let cmd = ProcessCommandBuilder::build_list_command(None, None, Some("nginx"));
        // awk preserves the ps header (NR==1) so columnar parsing keeps working,
        // and matches rows containing the lowercased pattern (case-insensitive).
        assert!(cmd.contains("awk -v p='nginx'"));
        assert!(cmd.contains("NR==1"));
        assert!(cmd.contains("index(tolower($0), p)"));
    }

    // ── build_kill_command ──────────────────────────────────────────

    #[test]
    fn test_kill_default_signal() {
        let cmd = ProcessCommandBuilder::build_kill_command(1234, None).unwrap();
        assert_eq!(cmd, "kill -TERM 1234");
    }

    #[test]
    fn test_kill_custom_signal() {
        let cmd = ProcessCommandBuilder::build_kill_command(1234, Some("9")).unwrap();
        assert_eq!(cmd, "kill -9 1234");
    }

    #[test]
    fn test_kill_pid_0_denied() {
        assert!(ProcessCommandBuilder::build_kill_command(0, None).is_err());
    }

    #[test]
    fn test_kill_pid_1_denied() {
        assert!(ProcessCommandBuilder::build_kill_command(1, None).is_err());
    }

    // ── validate_signal ─────────────────────────────────────────────

    #[test]
    fn test_validate_signal_allowed() {
        assert!(ProcessCommandBuilder::validate_signal("TERM").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("KILL").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("HUP").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("9").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("15").is_ok());
    }

    #[test]
    fn test_validate_signal_denied() {
        assert!(ProcessCommandBuilder::validate_signal("INVALID").is_err());
        assert!(ProcessCommandBuilder::validate_signal("").is_err());
    }

    // ── build_top_command ───────────────────────────────────────────

    #[test]
    fn test_top_default() {
        let cmd = ProcessCommandBuilder::build_top_command(None, None, None);
        assert!(cmd.contains("--sort=-'%cpu'"));
        assert!(cmd.contains("head -n 21"));
    }

    #[test]
    fn test_top_custom_sort() {
        let cmd = ProcessCommandBuilder::build_top_command(Some("%mem"), None, Some(10));
        assert!(cmd.contains("--sort=-'%mem'"));
        assert!(cmd.contains("head -n 11"));
    }

    #[test]
    fn test_top_with_user() {
        let cmd = ProcessCommandBuilder::build_top_command(None, Some("www-data"), None);
        assert!(cmd.contains("-u 'www-data'"));
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_list_injection_in_user() {
        let cmd = ProcessCommandBuilder::build_list_command(Some("root; rm -rf /"), None, None);
        assert!(cmd.contains("-u 'root; rm -rf /'"));
    }

    #[test]
    fn test_list_injection_in_sort_by() {
        let cmd = ProcessCommandBuilder::build_list_command(None, Some("%mem; whoami"), None);
        assert!(cmd.contains("--sort=-'%mem; whoami'"));
    }

    #[test]
    fn test_list_injection_in_filter() {
        let cmd =
            ProcessCommandBuilder::build_list_command(None, None, Some("nginx | cat /etc/passwd"));
        // The filter is shell-escaped and passed via awk -v as a literal
        // string variable, so pipe metacharacters cannot inject commands.
        assert!(cmd.contains("awk -v p='nginx | cat /etc/passwd'"));
    }

    #[test]
    fn test_top_injection_in_user() {
        let cmd = ProcessCommandBuilder::build_top_command(None, Some("$(id)"), None);
        assert!(cmd.contains("-u '$(id)'"));
    }

    #[test]
    fn test_top_injection_in_sort_by() {
        let cmd = ProcessCommandBuilder::build_top_command(Some("cpu; rm /"), None, None);
        assert!(cmd.contains("--sort=-'cpu; rm /'"));
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_list_all_options() {
        let cmd = ProcessCommandBuilder::build_list_command(
            Some("www-data"),
            Some("%mem"),
            Some("apache"),
        );
        assert!(cmd.contains("-u 'www-data'"));
        assert!(cmd.contains("--sort=-'%mem'"));
        assert!(cmd.contains("awk -v p='apache'"));
    }

    #[test]
    fn test_top_all_options() {
        let cmd = ProcessCommandBuilder::build_top_command(Some("%mem"), Some("nginx"), Some(50));
        assert!(cmd.contains("-u 'nginx'"));
        assert!(cmd.contains("--sort=-'%mem'"));
        assert!(cmd.contains("head -n 51")); // count + 1
    }

    // ============== Kill Edge Cases ==============

    #[test]
    fn test_kill_pid_2_allowed() {
        let cmd = ProcessCommandBuilder::build_kill_command(2, None).unwrap();
        assert_eq!(cmd, "kill -TERM 2");
    }

    #[test]
    fn test_kill_large_pid() {
        let cmd = ProcessCommandBuilder::build_kill_command(u32::MAX, None).unwrap();
        assert!(cmd.contains(&u32::MAX.to_string()));
    }

    #[test]
    fn test_kill_pid_0_error_message() {
        let result = ProcessCommandBuilder::build_kill_command(0, None);
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("PID 0"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_kill_pid_1_error_message() {
        let result = ProcessCommandBuilder::build_kill_command(1, None);
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("PID 1"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_kill_named_signal() {
        let cmd = ProcessCommandBuilder::build_kill_command(5678, Some("KILL")).unwrap();
        assert_eq!(cmd, "kill -KILL 5678");
    }

    // ============== Top Edge Cases ==============

    #[test]
    fn test_top_count_zero() {
        let cmd = ProcessCommandBuilder::build_top_command(None, None, Some(0));
        assert!(cmd.contains("head -n 1"));
    }

    #[test]
    fn test_top_count_one() {
        let cmd = ProcessCommandBuilder::build_top_command(None, None, Some(1));
        assert!(cmd.contains("head -n 2"));
    }

    #[test]
    fn test_top_count_large() {
        let cmd = ProcessCommandBuilder::build_top_command(None, None, Some(1000));
        assert!(cmd.contains("head -n 1001"));
    }

    // ============== validate_signal Additional Tests ==============

    #[test]
    fn test_validate_signal_all_named() {
        assert!(ProcessCommandBuilder::validate_signal("INT").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("QUIT").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("USR1").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("USR2").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("STOP").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("CONT").is_ok());
    }

    #[test]
    fn test_validate_signal_all_numeric() {
        assert!(ProcessCommandBuilder::validate_signal("1").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("2").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("3").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("10").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("12").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("18").is_ok());
        assert!(ProcessCommandBuilder::validate_signal("19").is_ok());
    }

    #[test]
    fn test_validate_signal_lowercase_rejected() {
        assert!(ProcessCommandBuilder::validate_signal("term").is_err());
        assert!(ProcessCommandBuilder::validate_signal("kill").is_err());
        assert!(ProcessCommandBuilder::validate_signal("hup").is_err());
    }

    #[test]
    fn test_validate_signal_error_message() {
        let result = ProcessCommandBuilder::validate_signal("INVALID");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("TERM"));
                assert!(reason.contains("KILL"));
                assert!(reason.contains("not allowed"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ============== List Behavior ==============

    #[test]
    fn test_list_user_overrides_ps_aux() {
        let cmd = ProcessCommandBuilder::build_list_command(Some("root"), None, None);
        assert!(cmd.starts_with("ps -u 'root'"));
        assert!(!cmd.contains("ps aux"));
        assert!(cmd.contains("-o pid,ppid,%cpu,%mem"));
    }
}
