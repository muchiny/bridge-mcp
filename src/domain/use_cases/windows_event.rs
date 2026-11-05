//! Windows Event Log Command Builder
//!
//! Builds `PowerShell` commands for querying and exporting Windows Event Logs
//! via SSH. Supports log querying with filters, source listing, tailing,
//! and exporting operations.

use crate::config::ShellType;
use crate::domain::use_cases::shell::escape;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    escape(s, ShellType::PowerShell)
}

/// Validates a Windows Event Log name to prevent command injection.
///
/// Log names must contain only alphanumeric characters, hyphens, underscores,
/// forward slashes, and spaces.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the log name is invalid.
pub fn validate_log_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Log name cannot be empty".to_string(),
        });
    }
    // `wevtutil` reads a word that starts with `/` or `-` as a switch.
    if name.starts_with(['/', '-']) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid log name '{name}'. It must not start with '/' or '-': wevtutil \
                 would read it as a switch."
            ),
        });
    }
    if name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/' || c == ' ')
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid log name '{name}'. \
                 Only alphanumeric, hyphen, underscore, forward slash, and space allowed.",
            ),
        })
    }
}

/// Validates the destination file of an event log export.
///
/// Only an absolute drive-letter path is accepted (`C:\Logs\x.evtx`,
/// `C:/Logs/x.evtx`): a UNC path (`\\host\share`, `//host/share`) would make the
/// host write the export to a remote share and authenticate to it with its own
/// credentials, and a leading `-` or `/` is read by `wevtutil` as a switch. After
/// the drive, only alphanumeric characters, separators, hyphen, underscore, space,
/// dot, parentheses, apostrophe and `~` are allowed (`C:\Program Files (x86)\…`,
/// `C:\Users\o'brien\…`, `C:\PROGRA~2\…`): inside the single-quoted `PowerShell`
/// literal the builder emits they are inert (the apostrophe is doubled), and
/// `wevtutil` takes them literally. That excludes `"` (Windows `PowerShell` 5.1
/// passes it unescaped to the native command line, where the CRT would strip it
/// and could expose a UNC path or split the argument), `?` (`\\??\UNC\…`), `*`, `|`,
/// `<`, `>`, `:` (alternate data streams) and control characters. A trailing
/// separator is refused too: it names a directory, and before a closing quote a
/// backslash escapes that quote.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the path is not a plain
/// drive-letter file path.
pub fn validate_export_file(file: &str) -> Result<()> {
    let mut head = file.chars();
    let drive_path = matches!(
        (head.next(), head.next(), head.next()),
        (Some(drive), Some(':'), Some('\\' | '/')) if drive.is_ascii_alphabetic()
    );
    let plain = file.chars().skip(2).all(|c| {
        c.is_alphanumeric()
            || matches!(
                c,
                '\\' | '/' | '-' | '_' | ' ' | '.' | '(' | ')' | '\'' | '~'
            )
    });
    if !drive_path || !plain || file.ends_with(['\\', '/']) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid export file '{file}'. It must be a local drive-letter file path \
                 (C:\\dir\\file.evtx): no UNC path, no double quote, and only alphanumeric, \
                 separator, hyphen, underscore, space, dot, parenthesis, apostrophe and \
                 tilde characters."
            ),
        });
    }
    Ok(())
}

/// Builds Windows Event Log `PowerShell` commands for remote execution.
pub struct WindowsEventCommandBuilder;

impl WindowsEventCommandBuilder {
    /// Build a `Get-WinEvent` query command.
    ///
    /// When `after` is provided, constructs a `FilterHashtable` query with a
    /// `StartTime` filter. Otherwise, queries by `-LogName` directly.
    ///
    /// Constructs:
    /// - With `after`: `Get-WinEvent -FilterHashtable @{LogName='{log}'; StartTime='{after}'}
    ///   -MaxEvents {count} | Format-Table TimeCreated,Id,LevelDisplayName,Message -AutoSize`
    /// - Without `after`: `Get-WinEvent -LogName '{log}' -MaxEvents {count}
    ///   | Format-Table TimeCreated,Id,LevelDisplayName,Message -AutoSize`
    #[must_use]
    pub fn build_query_command(log: &str, count: u32, after: Option<&str>) -> String {
        if let Some(after_val) = after {
            format!(
                "Get-WinEvent -FilterHashtable @{{LogName={}; StartTime={}}} \
                 -MaxEvents {count} | Format-Table TimeCreated,Id,LevelDisplayName,Message -AutoSize",
                ps_escape(log),
                ps_escape(after_val),
            )
        } else {
            format!(
                "Get-WinEvent -LogName {} -MaxEvents {count} \
                 | Format-Table TimeCreated,Id,LevelDisplayName,Message -AutoSize",
                ps_escape(log),
            )
        }
    }

    /// Build a command to list available event log sources.
    ///
    /// Constructs: `Get-WinEvent -ListLog * | Where-Object RecordCount -gt 0
    /// | Select-Object LogName,RecordCount,LastWriteTime
    /// | Sort-Object LastWriteTime -Descending | Format-Table -AutoSize`
    #[must_use]
    pub fn build_sources_command() -> String {
        "Get-WinEvent -ListLog * \
         | Where-Object RecordCount -gt 0 \
         | Select-Object LogName,RecordCount,LastWriteTime \
         | Sort-Object LastWriteTime -Descending \
         | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a tail command for recent events from a specific log.
    ///
    /// Constructs: `Get-WinEvent -LogName '{log}' -MaxEvents {count}
    /// | Format-Table TimeCreated,Id,LevelDisplayName,Message -Wrap`
    #[must_use]
    pub fn build_tail_command(log: &str, count: u32) -> String {
        format!(
            "Get-WinEvent -LogName {} -MaxEvents {count} \
             | Format-Table TimeCreated,Id,LevelDisplayName,Message -Wrap",
            ps_escape(log),
        )
    }

    /// Build a command to export an event log to a file.
    ///
    /// Constructs: `wevtutil epl '{log}' '{file}'`
    #[must_use]
    pub fn build_export_command(log: &str, file: &str) -> String {
        format!("wevtutil epl {} {}", ps_escape(log), ps_escape(file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_log_name ──────────────────────────────────────────

    #[test]
    fn test_validate_log_name_valid_simple() {
        assert!(validate_log_name("Application").is_ok());
        assert!(validate_log_name("System").is_ok());
        assert!(validate_log_name("Security").is_ok());
    }

    #[test]
    fn test_validate_log_name_valid_with_hyphens_underscores() {
        assert!(validate_log_name("My-Custom-Log").is_ok());
        assert!(validate_log_name("My_Custom_Log").is_ok());
    }

    #[test]
    fn test_validate_log_name_valid_with_slashes() {
        assert!(validate_log_name("Microsoft-Windows-Sysmon/Operational").is_ok());
        assert!(validate_log_name("Microsoft-Windows-PowerShell/Operational").is_ok());
    }

    #[test]
    fn test_validate_log_name_valid_with_spaces() {
        assert!(validate_log_name("Windows PowerShell").is_ok());
    }

    #[test]
    fn test_validate_log_name_refuses_a_leading_switch_character() {
        for name in ["/r", "-x", "/lf"] {
            let err = validate_log_name(name).expect_err(name);
            assert!(err.to_string().contains("must not start with"), "{err}");
        }
    }

    #[test]
    fn test_validate_export_file_refuses_unc_and_switches() {
        for file in [
            "\\\\attacker\\share\\x.evtx",
            "//attacker/share/x.evtx",
            "/ow:true",
            "-ow",
            "",
        ] {
            assert!(validate_export_file(file).is_err(), "{file}");
        }
        for file in [
            "C:\\Logs\\x.evtx",
            "d:/Logs/x.evtx",
            "C:\\My Logs\\x.1.evtx",
            "C:\\Program Files (x86)\\MyApp\\Logs\\sec.evtx",
            "C:\\Users\\o'brien\\x.evtx",
            "C:\\PROGRA~2\\x.evtx",
        ] {
            assert!(validate_export_file(file).is_ok(), "{file}");
        }
    }

    /// A `"` reaches the native command line unescaped under Windows
    /// `PowerShell` 5.1: the quoted UNC form must not get through.
    #[test]
    fn test_validate_export_file_refuses_quotes_and_non_drive_paths() {
        for file in [
            "\"\\\\attacker\\share\\loot.evtx\"",
            "\"//attacker/share/loot.evtx\"",
            " \\\\attacker\\share\\x.evtx",
            "C:\\Logs\\x\".evtx",
            "\\\\??\\UNC\\attacker\\share\\x.evtx",
            "C:\\x.evtx:stream",
            "C:\\Logs\\",
            "C:x.evtx",
            "x.evtx",
            "\\Logs\\x.evtx",
            "C:\\x\n.evtx",
            "C:\\a?b.evtx",
            "C:\\a*.evtx",
            "C:\\a|b.evtx",
            "C:\\a<b.evtx",
            "C:\\a>b.evtx",
            "C:\\a\"b.evtx",
            "C:\\a\tb.evtx",
            "C:\\a:b:c.evtx",
        ] {
            assert!(validate_export_file(file).is_err(), "{file:?}");
        }
    }

    #[test]
    fn test_validate_log_name_empty() {
        assert!(validate_log_name("").is_err());
    }

    #[test]
    fn test_validate_log_name_injection_semicolon() {
        assert!(validate_log_name("System; Remove-Item -Recurse C:\\").is_err());
    }

    #[test]
    fn test_validate_log_name_injection_pipe() {
        assert!(validate_log_name("System | Get-Content C:\\secret.txt").is_err());
    }

    #[test]
    fn test_validate_log_name_injection_dollar() {
        assert!(validate_log_name("System$(whoami)").is_err());
    }

    #[test]
    fn test_validate_log_name_injection_ampersand() {
        assert!(validate_log_name("System && whoami").is_err());
    }

    #[test]
    fn test_validate_log_name_injection_backtick() {
        assert!(validate_log_name("System`id`").is_err());
    }

    #[test]
    fn test_validate_log_name_error_message() {
        let result = validate_log_name("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_log_name_empty_error_message() {
        let result = validate_log_name("");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("cannot be empty"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ── build_query_command ────────────────────────────────────────

    #[test]
    fn test_query_command_without_after() {
        let cmd = WindowsEventCommandBuilder::build_query_command("Application", 50, None);
        assert!(cmd.starts_with("Get-WinEvent -LogName 'Application' -MaxEvents 50"));
        assert!(cmd.contains("Format-Table TimeCreated,Id,LevelDisplayName,Message -AutoSize"));
    }

    #[test]
    fn test_query_command_with_after() {
        let cmd = WindowsEventCommandBuilder::build_query_command(
            "System",
            100,
            Some("2024-01-01T00:00:00"),
        );
        assert!(cmd.contains("FilterHashtable"));
        assert!(cmd.contains("LogName='System'"));
        assert!(cmd.contains("StartTime='2024-01-01T00:00:00'"));
        assert!(cmd.contains("-MaxEvents 100"));
        assert!(cmd.contains("Format-Table TimeCreated,Id,LevelDisplayName,Message -AutoSize"));
    }

    #[test]
    fn test_query_command_count_one() {
        let cmd = WindowsEventCommandBuilder::build_query_command("Security", 1, None);
        assert!(cmd.contains("-MaxEvents 1"));
    }

    #[test]
    fn test_query_command_large_count() {
        let cmd = WindowsEventCommandBuilder::build_query_command("Application", 1_000_000, None);
        assert!(cmd.contains("-MaxEvents 1000000"));
    }

    #[test]
    fn test_query_command_injection_in_log() {
        let cmd =
            WindowsEventCommandBuilder::build_query_command("System'; Remove-Item C:\\", 10, None);
        // The single quote in the log name gets escaped (doubled) by PowerShell escaping
        assert!(cmd.contains("'System''; Remove-Item C:\\'"));
    }

    #[test]
    fn test_query_command_injection_in_after() {
        let cmd = WindowsEventCommandBuilder::build_query_command(
            "System",
            10,
            Some("2024-01-01'; whoami; '"),
        );
        // Single quotes inside the after value are doubled
        assert!(cmd.contains("'2024-01-01''; whoami; '''"));
    }

    // ── build_sources_command ──────────────────────────────────────

    #[test]
    fn test_sources_command() {
        let cmd = WindowsEventCommandBuilder::build_sources_command();
        assert!(cmd.contains("Get-WinEvent -ListLog *"));
        assert!(cmd.contains("Where-Object RecordCount -gt 0"));
        assert!(cmd.contains("Select-Object LogName,RecordCount,LastWriteTime"));
        assert!(cmd.contains("Sort-Object LastWriteTime -Descending"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_tail_command ─────────────────────────────────────────

    #[test]
    fn test_tail_command() {
        let cmd = WindowsEventCommandBuilder::build_tail_command("Application", 20);
        assert!(cmd.starts_with("Get-WinEvent -LogName 'Application' -MaxEvents 20"));
        assert!(cmd.contains("Format-Table TimeCreated,Id,LevelDisplayName,Message -Wrap"));
    }

    #[test]
    fn test_tail_command_count_one() {
        let cmd = WindowsEventCommandBuilder::build_tail_command("System", 1);
        assert!(cmd.contains("-MaxEvents 1"));
    }

    #[test]
    fn test_tail_command_injection_in_log() {
        let cmd = WindowsEventCommandBuilder::build_tail_command("System'; whoami; '", 10);
        // Single quotes are doubled by PowerShell escaping
        assert!(cmd.contains("'System''; whoami; '''"));
    }

    #[test]
    fn test_tail_vs_query_formatting() {
        let tail = WindowsEventCommandBuilder::build_tail_command("Application", 10);
        let query = WindowsEventCommandBuilder::build_query_command("Application", 10, None);

        // Tail uses -Wrap, query uses -AutoSize
        assert!(tail.contains("-Wrap"));
        assert!(!tail.contains("-AutoSize"));
        assert!(query.contains("-AutoSize"));
        assert!(!query.contains("-Wrap"));
    }

    // ── build_export_command ───────────────────────────────────────

    #[test]
    fn test_export_command() {
        let cmd =
            WindowsEventCommandBuilder::build_export_command("Application", "C:\\Logs\\app.evtx");
        assert_eq!(cmd, "wevtutil epl 'Application' 'C:\\Logs\\app.evtx'");
    }

    #[test]
    fn test_export_command_injection_in_log() {
        let cmd =
            WindowsEventCommandBuilder::build_export_command("System'; whoami; '", "out.evtx");
        assert!(cmd.contains("'System''; whoami; '''"));
    }

    #[test]
    fn test_export_command_injection_in_file() {
        let cmd =
            WindowsEventCommandBuilder::build_export_command("System", "out.evtx'; whoami; '");
        assert!(cmd.contains("'out.evtx''; whoami; '''"));
    }

    #[test]
    fn test_export_command_keeps_parentheses_and_doubles_apostrophe() {
        let cmd = WindowsEventCommandBuilder::build_export_command(
            "System",
            "C:\\Users\\o'brien\\Program Files (x86)\\PROGRA~2.evtx",
        );
        assert_eq!(
            cmd,
            "wevtutil epl 'System' 'C:\\Users\\o''brien\\Program Files (x86)\\PROGRA~2.evtx'"
        );
    }

    #[test]
    fn test_export_command_unc_path() {
        let cmd = WindowsEventCommandBuilder::build_export_command(
            "Application",
            "\\\\server\\share\\logs\\app.evtx",
        );
        assert!(cmd.contains("'\\\\server\\share\\logs\\app.evtx'"));
    }

    // ── Log names with special valid characters ────────────────────

    #[test]
    fn test_query_command_log_with_slash() {
        let cmd = WindowsEventCommandBuilder::build_query_command(
            "Microsoft-Windows-Sysmon/Operational",
            25,
            None,
        );
        assert!(cmd.contains("'Microsoft-Windows-Sysmon/Operational'"));
    }

    #[test]
    fn test_tail_command_log_with_space() {
        let cmd = WindowsEventCommandBuilder::build_tail_command("Windows PowerShell", 10);
        assert!(cmd.contains("'Windows PowerShell'"));
    }

    #[test]
    fn test_export_command_log_with_underscore() {
        let cmd = WindowsEventCommandBuilder::build_export_command("My_Custom_Log", "C:\\out.evtx");
        assert!(cmd.contains("'My_Custom_Log'"));
    }
}
