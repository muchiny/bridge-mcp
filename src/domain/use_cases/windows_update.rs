//! Windows Update Command Builder
//!
//! Builds `PowerShell` commands for managing Windows Updates via SSH.
//! Supports listing available updates, viewing update history, installing
//! specific updates by KB ID, searching for updates, and checking reboot status.

use crate::config::ShellType;
use crate::domain::use_cases::shell::escape;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    escape(s, ShellType::PowerShell)
}

/// Validates a KB article ID to prevent command injection.
///
/// KB IDs must match the pattern `KB` followed by one or more digits
/// (e.g., `KB5034441`). Only uppercase `KB` prefix with ASCII digits allowed.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the KB ID is invalid.
pub fn validate_kb_id(kb: &str) -> Result<()> {
    if kb.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "KB ID cannot be empty".to_string(),
        });
    }
    // Must start with "KB" followed by one or more digits
    if kb.starts_with("KB") && kb.len() > 2 && kb[2..].chars().all(|c| c.is_ascii_digit()) {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid KB ID '{kb}'. \
                 Must match pattern KB followed by digits (e.g., KB5034441).",
            ),
        })
    }
}

/// Builds `PowerShell` commands for managing Windows Updates.
pub struct WindowsUpdateCommandBuilder;

impl WindowsUpdateCommandBuilder {
    /// Build a command to list available Windows updates.
    ///
    /// Constructs: `Get-WindowsUpdate | Select-Object KB,Title,Size,Status
    /// | Format-Table -AutoSize`
    #[must_use]
    pub fn build_list_command() -> String {
        "Get-WindowsUpdate \
         | Select-Object KB,Title,Size,Status \
         | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a command to view update history for a given number of days.
    ///
    /// Constructs: `Get-WUHistory -MaxDate (Get-Date).AddDays(-{days})
    /// | Select-Object Date,Title,Result | Format-Table -AutoSize`
    #[must_use]
    pub fn build_history_command(days: u32) -> String {
        format!(
            "Get-WUHistory -MaxDate (Get-Date).AddDays(-{days}) \
             | Select-Object Date,Title,Result \
             | Format-Table -AutoSize",
        )
    }

    /// Build a command to install a specific update by KB article ID.
    ///
    /// Constructs: `Install-WindowsUpdate -KBArticleID {kb}
    /// -AcceptAll -AutoReboot:$false`
    #[must_use]
    pub fn build_install_command(kb: &str) -> String {
        format!(
            "Install-WindowsUpdate -KBArticleID {} -AcceptAll -AutoReboot:$false",
            ps_escape(kb),
        )
    }

    /// Build a command to search for updates matching a query.
    ///
    /// The query matches anywhere in the title.
    ///
    /// `Get-WindowsUpdate -Title` takes a **regex**, not a glob. Wrapping the
    /// query in `*` produced `*Security*`, which the .NET regex engine
    /// rejects outright — `parsing "*Security*" - Quantifier {x,y} following
    /// nothing` — so every search failed. The query is escaped as a regex
    /// literal and wrapped in `.*` instead.
    ///
    /// Constructs: `Get-WindowsUpdate -Title '.*{query}.*'
    /// | Select-Object KB,Title,Size | Format-Table -AutoSize`
    #[must_use]
    pub fn build_search_command(query: &str) -> String {
        let escaped: String = query
            .chars()
            .flat_map(|c| {
                if r"\^$.|?*+()[]{}".contains(c) {
                    vec!['\\', c]
                } else {
                    vec![c]
                }
            })
            .collect();
        let pattern = format!(".*{escaped}.*");
        format!(
            "Get-WindowsUpdate -Title {} \
             | Select-Object KB,Title,Size \
             | Format-Table -AutoSize",
            ps_escape(&pattern),
        )
    }

    /// Build a command to check the reboot status after updates.
    ///
    /// Constructs: `Get-WURebootStatus`
    #[must_use]
    pub fn build_reboot_status_command() -> String {
        "Get-WURebootStatus".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_kb_id ──────────────────────────────────────────────

    #[test]
    fn test_validate_kb_id_valid() {
        assert!(validate_kb_id("KB5034441").is_ok());
        assert!(validate_kb_id("KB123456").is_ok());
        assert!(validate_kb_id("KB1").is_ok());
    }

    #[test]
    fn test_validate_kb_id_empty() {
        assert!(validate_kb_id("").is_err());
    }

    #[test]
    fn test_validate_kb_id_no_prefix() {
        assert!(validate_kb_id("5034441").is_err());
        assert!(validate_kb_id("1234").is_err());
    }

    #[test]
    fn test_validate_kb_id_lowercase_prefix() {
        assert!(validate_kb_id("kb5034441").is_err());
    }

    #[test]
    fn test_validate_kb_id_only_prefix() {
        assert!(validate_kb_id("KB").is_err());
    }

    #[test]
    fn test_validate_kb_id_non_digit_suffix() {
        assert!(validate_kb_id("KB503abc").is_err());
        assert!(validate_kb_id("KBabc").is_err());
    }

    #[test]
    fn test_validate_kb_id_injection() {
        assert!(validate_kb_id("KB123; whoami").is_err());
        assert!(validate_kb_id("KB123$(hostname)").is_err());
        assert!(validate_kb_id("KB123|Out-File").is_err());
        assert!(validate_kb_id("KB123&dir").is_err());
    }

    #[test]
    fn test_validate_kb_id_special_chars_rejected() {
        assert!(validate_kb_id("KB123`id`").is_err());
        assert!(validate_kb_id("KB123@host").is_err());
        assert!(validate_kb_id("KB123#1").is_err());
        assert!(validate_kb_id("KB123$env").is_err());
    }

    #[test]
    fn test_validate_kb_id_error_message_contains_input() {
        let result = validate_kb_id("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_kb_id_empty_error_message() {
        let result = validate_kb_id("");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("cannot be empty"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ── build_list_command ──────────────────────────────────────────

    #[test]
    fn test_list_command() {
        let cmd = WindowsUpdateCommandBuilder::build_list_command();
        assert!(cmd.contains("Get-WindowsUpdate"));
        assert!(cmd.contains("Select-Object KB,Title,Size,Status"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_history_command ───────────────────────────────────────

    #[test]
    fn test_history_command() {
        let cmd = WindowsUpdateCommandBuilder::build_history_command(30);
        assert!(cmd.contains("Get-WUHistory"));
        assert!(cmd.contains("(Get-Date).AddDays(-30)"));
        assert!(cmd.contains("Select-Object Date,Title,Result"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    #[test]
    fn test_history_command_one_day() {
        let cmd = WindowsUpdateCommandBuilder::build_history_command(1);
        assert!(cmd.contains("AddDays(-1)"));
    }

    #[test]
    fn test_history_command_large_days() {
        let cmd = WindowsUpdateCommandBuilder::build_history_command(365);
        assert!(cmd.contains("AddDays(-365)"));
    }

    #[test]
    fn test_history_command_zero_days() {
        let cmd = WindowsUpdateCommandBuilder::build_history_command(0);
        assert!(cmd.contains("AddDays(-0)"));
    }

    // ── build_install_command ───────────────────────────────────────

    #[test]
    fn test_install_command() {
        let cmd = WindowsUpdateCommandBuilder::build_install_command("KB5034441");
        assert_eq!(
            cmd,
            "Install-WindowsUpdate -KBArticleID 'KB5034441' -AcceptAll -AutoReboot:$false"
        );
    }

    #[test]
    fn test_install_command_injection() {
        let cmd = WindowsUpdateCommandBuilder::build_install_command("KB123; whoami");
        assert!(cmd.contains("'KB123; whoami'"));
    }

    #[test]
    fn test_install_command_single_quote() {
        let cmd = WindowsUpdateCommandBuilder::build_install_command("KB'123");
        assert!(cmd.contains("'KB''123'"));
    }

    #[test]
    fn test_install_command_dollar_sign() {
        let cmd = WindowsUpdateCommandBuilder::build_install_command("$env:KB");
        assert!(cmd.contains("'$env:KB'"));
    }

    #[test]
    fn test_install_command_pipe() {
        let cmd = WindowsUpdateCommandBuilder::build_install_command("KB123|Out-File");
        assert!(cmd.contains("'KB123|Out-File'"));
    }

    #[test]
    fn test_install_command_backtick() {
        let cmd = WindowsUpdateCommandBuilder::build_install_command("KB123`n");
        assert!(cmd.contains("'KB123`n'"));
    }

    #[test]
    fn test_install_command_no_auto_reboot() {
        let cmd = WindowsUpdateCommandBuilder::build_install_command("KB5034441");
        assert!(cmd.contains("-AutoReboot:$false"));
    }

    // ── build_search_command ────────────────────────────────────────

    #[test]
    fn test_search_command() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("Security");
        assert!(cmd.contains("Get-WindowsUpdate -Title '.*Security.*'"));
        assert!(cmd.contains("Select-Object KB,Title,Size"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    /// `-Title` is a regex. A glob there is not just ineffective, it is a
    /// parse error on the server: `*Security*` made the .NET engine reject
    /// the whole pattern. Regex metacharacters in the query must arrive
    /// escaped, not interpreted.
    #[test]
    fn test_search_command_escapes_regex_metacharacters() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("C++ (x86)");
        assert!(
            cmd.contains(r".*C\+\+ \(x86\).*"),
            "metacharacters must be escaped, got: {cmd}"
        );
        assert!(!cmd.contains("'*"), "no bare glob may reach -Title: {cmd}");
    }

    #[test]
    fn test_search_command_with_spaces() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("Cumulative Update");
        assert!(cmd.contains("'.*Cumulative Update.*'"));
    }

    #[test]
    fn test_search_command_injection() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("test'; whoami; '");
        // Single quotes are doubled by PowerShell escaping
        assert!(cmd.contains("'.*test''; whoami; ''.*'"));
    }

    #[test]
    fn test_search_command_dollar_sign() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("$env:test");
        // `$` is a regex anchor, so it is escaped too — which incidentally
        // also neutralises PowerShell expansion a second time.
        assert!(cmd.contains(r"'.*\$env:test.*'"));
    }

    #[test]
    fn test_search_command_pipe() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("test|Out-File");
        assert!(cmd.contains(r"'.*test\|Out-File.*'"));
    }

    #[test]
    fn test_search_command_backtick() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("test`n");
        // A backtick is not a regex metacharacter, so it passes through.
        assert!(cmd.contains("'.*test`n.*'"));
    }

    #[test]
    fn test_search_command_empty_query() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("");
        assert!(cmd.contains("'.*.*'"));
    }

    // ── build_reboot_status_command ─────────────────────────────────

    #[test]
    fn test_reboot_status_command() {
        let cmd = WindowsUpdateCommandBuilder::build_reboot_status_command();
        assert_eq!(cmd, "Get-WURebootStatus");
    }

    // ── Shell Injection Prevention ──────────────────────────────────

    #[test]
    fn test_single_quote_escaping_in_install() {
        let cmd = WindowsUpdateCommandBuilder::build_install_command("KB'test");
        assert!(cmd.contains("'KB''test'"));
    }

    #[test]
    fn test_dollar_variable_neutralized_in_search() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("$env:COMPUTERNAME");
        assert!(cmd.contains(r"'.*\$env:COMPUTERNAME.*'"));
    }

    #[test]
    fn test_semicolon_neutralized_in_install() {
        let cmd = WindowsUpdateCommandBuilder::build_install_command("KB123;bad");
        assert!(cmd.contains("'KB123;bad'"));
    }

    #[test]
    fn test_pipe_neutralized_in_search() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("test|bad");
        assert!(cmd.contains(r"'.*test\|bad.*'"));
    }

    // ── Edge Cases ──────────────────────────────────────────────────

    #[test]
    fn test_history_vs_list_difference() {
        let list = WindowsUpdateCommandBuilder::build_list_command();
        let history = WindowsUpdateCommandBuilder::build_history_command(30);
        assert!(list.contains("Get-WindowsUpdate"));
        assert!(history.contains("Get-WUHistory"));
    }

    #[test]
    fn test_search_wraps_in_regex_any() {
        let cmd = WindowsUpdateCommandBuilder::build_search_command("test");
        assert!(cmd.contains("'.*test.*'"));
    }
}
