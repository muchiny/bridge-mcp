//! Windows Process Command Builder
//!
//! Builds `PowerShell` commands for Windows process management and disk usage
//! diagnostics via SSH. Supports listing, info, kill, top, search by name,
//! and disk usage operations.

use std::fmt::Write;

use crate::config::ShellType;
use crate::domain::use_cases::shell;

/// Escape a string for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    shell::escape(s, ShellType::PowerShell)
}

/// Builds `PowerShell` commands for Windows process management.
pub struct WindowsProcessCommandBuilder;

impl WindowsProcessCommandBuilder {
    /// Build command to list all processes sorted by CPU usage descending.
    ///
    /// Constructs: `Get-Process | Select-Object Id,Name,CPU,WorkingSet64,StartTime
    /// | Sort-Object CPU -Descending | ConvertTo-Json`
    #[must_use]
    pub fn list() -> String {
        "Get-Process \
         | Select-Object Id,Name,CPU,WorkingSet64,StartTime \
         | Sort-Object CPU -Descending \
         | ConvertTo-Json"
            .to_string()
    }

    /// Build command to get detailed process info by PID.
    ///
    /// Constructs: `Get-Process -Id {pid} | Format-List *`
    #[must_use]
    pub fn info(pid: u32) -> String {
        format!("Get-Process -Id {pid} | Format-List *")
    }

    /// Build command to stop a process by PID.
    ///
    /// Constructs: `Stop-Process -Id {pid} [-Force]`
    #[must_use]
    pub fn kill(pid: u32, force: bool) -> String {
        let mut cmd = format!("Stop-Process -Id {pid}");
        if force {
            cmd.push_str(" -Force");
        }
        cmd
    }

    /// Build command to list the top N processes by CPU usage.
    ///
    /// Constructs: `Get-Process | Sort-Object CPU -Descending
    /// | Select-Object -First {count} Id,Name,CPU,WorkingSet64`
    #[must_use]
    pub fn top(count: u32) -> String {
        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "Get-Process | Sort-Object CPU -Descending \
             | Select-Object -First {count} Id,Name,CPU,WorkingSet64",
        );
        cmd
    }

    /// Build command to get processes by name.
    ///
    /// Constructs: `Get-Process -Name '{name}'`
    #[must_use]
    pub fn by_name(name: &str) -> String {
        format!("Get-Process -Name {}", ps_escape(name))
    }

    /// Build command to get disk usage for filesystem drives.
    ///
    /// Constructs: `Get-PSDrive -PSProvider FileSystem | Select-Object
    /// Name,Used,Free,@{N='Total';E={$_.Used+$_.Free}} | ConvertTo-Json`
    #[must_use]
    pub fn disk_usage() -> String {
        "Get-PSDrive -PSProvider FileSystem \
         | Select-Object Name,Used,Free,@{N='Total';E={$_.Used+$_.Free}} \
         | ConvertTo-Json"
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn by_name_keeps_a_unicode_quote_inside_the_literal() {
        assert_eq!(
            WindowsProcessCommandBuilder::by_name("a\u{2019}; Write-Output pwned; \u{2019}"),
            "Get-Process -Name 'a\u{2019}\u{2019}; Write-Output pwned; \u{2019}\u{2019}'"
        );
    }

    // ── list ────────────────────────────────────────────────────────

    #[test]
    fn test_list() {
        let cmd = WindowsProcessCommandBuilder::list();
        assert!(cmd.contains("Get-Process"));
        assert!(cmd.contains("Select-Object Id,Name,CPU,WorkingSet64,StartTime"));
        assert!(cmd.contains("Sort-Object CPU -Descending"));
        assert!(cmd.contains("ConvertTo-Json"));
    }

    // ── info ────────────────────────────────────────────────────────

    #[test]
    fn test_info() {
        let cmd = WindowsProcessCommandBuilder::info(1234);
        assert_eq!(cmd, "Get-Process -Id 1234 | Format-List *");
    }

    #[test]
    fn test_info_zero_pid() {
        let cmd = WindowsProcessCommandBuilder::info(0);
        assert!(cmd.contains("-Id 0"));
    }

    #[test]
    fn test_info_large_pid() {
        let cmd = WindowsProcessCommandBuilder::info(999_999);
        assert!(cmd.contains("-Id 999999"));
    }

    // ── kill ────────────────────────────────────────────────────────

    #[test]
    fn test_kill_graceful() {
        let cmd = WindowsProcessCommandBuilder::kill(1234, false);
        assert_eq!(cmd, "Stop-Process -Id 1234");
        assert!(!cmd.contains("-Force"));
    }

    #[test]
    fn test_kill_force() {
        let cmd = WindowsProcessCommandBuilder::kill(1234, true);
        assert_eq!(cmd, "Stop-Process -Id 1234 -Force");
    }

    #[test]
    fn test_kill_zero_pid() {
        let cmd = WindowsProcessCommandBuilder::kill(0, true);
        assert!(cmd.contains("-Id 0"));
        assert!(cmd.contains("-Force"));
    }

    // ── top ─────────────────────────────────────────────────────────

    #[test]
    fn test_top() {
        let cmd = WindowsProcessCommandBuilder::top(10);
        assert!(cmd.contains("Get-Process"));
        assert!(cmd.contains("Sort-Object CPU -Descending"));
        assert!(cmd.contains("Select-Object -First 10 Id,Name,CPU,WorkingSet64"));
    }

    #[test]
    fn test_top_one() {
        let cmd = WindowsProcessCommandBuilder::top(1);
        assert!(cmd.contains("-First 1"));
    }

    #[test]
    fn test_top_large_count() {
        let cmd = WindowsProcessCommandBuilder::top(1000);
        assert!(cmd.contains("-First 1000"));
    }

    // ── by_name ─────────────────────────────────────────────────────

    #[test]
    fn test_by_name() {
        let cmd = WindowsProcessCommandBuilder::by_name("chrome");
        assert_eq!(cmd, "Get-Process -Name 'chrome'");
    }

    #[test]
    fn test_by_name_injection() {
        let cmd = WindowsProcessCommandBuilder::by_name("proc; whoami");
        assert!(cmd.contains("'proc; whoami'"));
    }

    #[test]
    fn test_by_name_single_quote_escape() {
        let cmd = WindowsProcessCommandBuilder::by_name("it's");
        assert!(cmd.contains("'it''s'"));
    }

    #[test]
    fn test_by_name_dollar_variable() {
        let cmd = WindowsProcessCommandBuilder::by_name("$env:PATH");
        assert!(cmd.contains("'$env:PATH'"));
    }

    #[test]
    fn test_by_name_pipe_neutralized() {
        let cmd = WindowsProcessCommandBuilder::by_name("proc|Out-File");
        assert!(cmd.contains("'proc|Out-File'"));
    }

    // ── disk_usage ──────────────────────────────────────────────────

    #[test]
    fn test_disk_usage() {
        let cmd = WindowsProcessCommandBuilder::disk_usage();
        assert!(cmd.contains("Get-PSDrive -PSProvider FileSystem"));
        assert!(cmd.contains("Name,Used,Free"));
        assert!(cmd.contains("N='Total'"));
        assert!(cmd.contains("ConvertTo-Json"));
    }

    // ── Shell Injection Prevention ──────────────────────────────────

    #[test]
    fn test_dollar_variable_neutralized_in_by_name() {
        let cmd = WindowsProcessCommandBuilder::by_name("$env:COMPUTERNAME");
        assert!(cmd.contains("'$env:COMPUTERNAME'"));
    }

    #[test]
    fn test_backtick_neutralized_in_by_name() {
        let cmd = WindowsProcessCommandBuilder::by_name("proc`n");
        assert!(cmd.contains("'proc`n'"));
    }

    #[test]
    fn test_semicolon_neutralized_in_by_name() {
        let cmd = WindowsProcessCommandBuilder::by_name("proc;bad");
        assert!(cmd.contains("'proc;bad'"));
    }

    // ── Edge Cases ───────────────────────────────────────────────────

    #[test]
    fn test_top_with_count_zero() {
        let cmd = WindowsProcessCommandBuilder::top(0);
        assert!(cmd.contains("-First 0"));
        assert!(cmd.contains("Get-Process"));
    }

    #[test]
    fn test_by_name_with_wildcard_chars() {
        let cmd = WindowsProcessCommandBuilder::by_name("chrome*");
        assert!(cmd.contains("'chrome*'"));
        let cmd2 = WindowsProcessCommandBuilder::by_name("sys?em");
        assert!(cmd2.contains("'sys?em'"));
    }

    #[test]
    fn test_by_name_with_backslash() {
        let cmd = WindowsProcessCommandBuilder::by_name("C:\\Windows\\proc");
        assert!(cmd.contains("'C:\\Windows\\proc'"));
    }

    #[test]
    fn test_by_name_empty_string() {
        let cmd = WindowsProcessCommandBuilder::by_name("");
        assert_eq!(cmd, "Get-Process -Name ''");
    }

    #[test]
    fn test_list_includes_json_output() {
        let cmd = WindowsProcessCommandBuilder::list();
        assert!(cmd.starts_with("Get-Process"));
        assert!(cmd.ends_with("ConvertTo-Json"));
        assert!(cmd.contains("Select-Object"));
        assert!(cmd.contains("Sort-Object CPU -Descending"));
    }
}
