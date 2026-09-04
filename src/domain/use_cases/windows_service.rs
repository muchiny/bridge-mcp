//! Windows Service Command Builder
//!
//! Builds `PowerShell` commands for remote Windows service management via SSH.
//! Supports status, start, stop, restart, list, enable, disable, config,
//! and event log retrieval operations.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

use super::shell;

/// Validates a Windows service name to prevent command injection.
///
/// Service names must be alphanumeric with hyphens, underscores, spaces, and dots.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the service name is invalid.
pub fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Service name cannot be empty".to_string(),
        });
    }
    if name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid service name '{name}'. \
                 Only alphanumeric, hyphen, underscore, space, and dot allowed.",
            ),
        })
    }
}

/// Escapes a value for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    shell::escape(s, ShellType::PowerShell)
}

/// Builds `PowerShell` commands for remote Windows service management.
pub struct WindowsServiceCommandBuilder;

impl WindowsServiceCommandBuilder {
    /// Build a `Get-Service` status command.
    ///
    /// Constructs: `Get-Service -Name {name} | Select-Object
    /// Name,DisplayName,Status,StartType,DependentServices | Format-List`
    #[must_use]
    pub fn build_status_command(name: &str) -> String {
        format!(
            "Get-Service -Name {} | Select-Object \
             Name,DisplayName,Status,StartType,DependentServices | Format-List",
            ps_escape(name),
        )
    }

    /// Build a `Start-Service` command.
    ///
    /// Constructs: `Start-Service -Name {name}; Get-Service -Name {name}
    /// | Select-Object Name,Status`
    #[must_use]
    pub fn build_start_command(name: &str) -> String {
        let escaped = ps_escape(name);
        format!(
            "Start-Service -Name {escaped}; \
             Get-Service -Name {escaped} | Select-Object Name,Status",
        )
    }

    /// Build a `Stop-Service` command.
    ///
    /// Constructs: `Stop-Service -Name {name} -Force; Get-Service -Name {name}
    /// | Select-Object Name,Status`
    #[must_use]
    pub fn build_stop_command(name: &str) -> String {
        let escaped = ps_escape(name);
        format!(
            "Stop-Service -Name {escaped} -Force; \
             Get-Service -Name {escaped} | Select-Object Name,Status",
        )
    }

    /// Build a `Restart-Service` command.
    ///
    /// Constructs: `Restart-Service -Name {name} -Force; Get-Service -Name {name}
    /// | Select-Object Name,Status`
    #[must_use]
    pub fn build_restart_command(name: &str) -> String {
        let escaped = ps_escape(name);
        format!(
            "Restart-Service -Name {escaped} -Force; \
             Get-Service -Name {escaped} | Select-Object Name,Status",
        )
    }

    /// Build a `Get-Service` list command.
    ///
    /// Constructs: `Get-Service | Select-Object Name,DisplayName,Status,StartType
    /// | Sort-Object Name | Format-Table -AutoSize`
    #[must_use]
    pub fn build_list_command() -> String {
        "Get-Service | Select-Object Name,DisplayName,Status,StartType \
         | Sort-Object Name | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a `Set-Service` enable command (sets startup type to Automatic).
    ///
    /// Constructs: `Set-Service -Name {name} -StartupType Automatic;
    /// Get-Service -Name {name} | Select-Object Name,StartType`
    #[must_use]
    pub fn build_enable_command(name: &str) -> String {
        let escaped = ps_escape(name);
        format!(
            "Set-Service -Name {escaped} -StartupType Automatic; \
             Get-Service -Name {escaped} | Select-Object Name,StartType",
        )
    }

    /// Build a `Set-Service` disable command (sets startup type to Disabled).
    ///
    /// Constructs: `Set-Service -Name {name} -StartupType Disabled;
    /// Get-Service -Name {name} | Select-Object Name,StartType`
    #[must_use]
    pub fn build_disable_command(name: &str) -> String {
        let escaped = ps_escape(name);
        format!(
            "Set-Service -Name {escaped} -StartupType Disabled; \
             Get-Service -Name {escaped} | Select-Object Name,StartType",
        )
    }

    /// Build a service configuration query command.
    ///
    /// Constructs: `Get-Service -Name {name} | Select-Object *;
    /// Get-CimInstance Win32_Service -Filter "Name='{name}'"
    /// | Select-Object PathName,StartMode,State,ProcessId`
    #[must_use]
    pub fn build_config_command(name: &str) -> String {
        let escaped = ps_escape(name);
        // PRECONDITION: `name` has passed [`validate_service_name`]. Every
        // caller in this crate does that first, and this builder is not safe
        // without it.
        //
        // The doubling below is NOT sufficient on its own, and the comment it
        // replaces claimed otherwise ("escape single quotes by doubling them
        // to prevent injection in the WMI filter clause"). The WMI filter sits
        // inside a PowerShell DOUBLE-quoted string, so a name carrying `"`
        // closes that string before WMI ever sees the value, and `$` or a
        // backtick would be expanded there. Doubling quotes addresses neither.
        // `validate_service_name` refuses all of them, which is what actually
        // holds this position.
        //
        // Found by `fuzz_windows_service_builder` on `S%3W3\"%3`, running the
        // builder directly; unreachable through the handlers.
        let wmi_safe = name.replace('\'', "''");
        format!(
            "Get-Service -Name {escaped} | Select-Object *; \
             Get-CimInstance Win32_Service -Filter \"Name='{wmi_safe}'\" \
             | Select-Object PathName,StartMode,State,ProcessId",
        )
    }

    /// Build a `Get-EventLog` command for retrieving event logs.
    ///
    /// Constructs: `Get-EventLog -LogName {log} -Newest {count}
    /// | Format-Table -AutoSize`
    #[must_use]
    pub fn build_event_logs_command(log: &str, count: u32) -> String {
        format!(
            "Get-EventLog -LogName {} -Newest {count} | Format-Table -AutoSize",
            ps_escape(log),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_service_name ───────────────────────────────────────

    #[test]
    fn test_validate_service_name_valid() {
        assert!(validate_service_name("wuauserv").is_ok());
        assert!(validate_service_name("Windows Update").is_ok());
        assert!(validate_service_name("my-service").is_ok());
        assert!(validate_service_name("my_service").is_ok());
        assert!(validate_service_name("svc.name").is_ok());
    }

    #[test]
    fn test_validate_service_name_empty() {
        assert!(validate_service_name("").is_err());
    }

    #[test]
    fn test_validate_service_name_injection() {
        assert!(validate_service_name("svc; Remove-Item C:\\").is_err());
        assert!(validate_service_name("svc && whoami").is_err());
        assert!(validate_service_name("svc$(hostname)").is_err());
        assert!(validate_service_name("svc|Out-File").is_err());
    }

    #[test]
    fn test_validate_service_name_special_chars_rejected() {
        assert!(validate_service_name("svc`id`").is_err());
        assert!(validate_service_name("svc@host").is_err());
        assert!(validate_service_name("svc#1").is_err());
        assert!(validate_service_name("svc$env").is_err());
    }

    #[test]
    fn test_validate_service_name_error_message() {
        let result = validate_service_name("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ── build_status_command ────────────────────────────────────────

    #[test]
    fn test_status_command() {
        let cmd = WindowsServiceCommandBuilder::build_status_command("wuauserv");
        assert_eq!(
            cmd,
            "Get-Service -Name 'wuauserv' | Select-Object \
             Name,DisplayName,Status,StartType,DependentServices | Format-List"
        );
    }

    #[test]
    fn test_status_command_with_space() {
        let cmd = WindowsServiceCommandBuilder::build_status_command("Windows Update");
        assert!(cmd.contains("'Windows Update'"));
    }

    #[test]
    fn test_status_command_injection() {
        let cmd = WindowsServiceCommandBuilder::build_status_command("svc; whoami");
        // PowerShell escape wraps in single quotes, neutralizing the semicolon
        assert!(cmd.contains("'svc; whoami'"));
    }

    // ── build_start_command ─────────────────────────────────────────

    #[test]
    fn test_start_command() {
        let cmd = WindowsServiceCommandBuilder::build_start_command("wuauserv");
        assert_eq!(
            cmd,
            "Start-Service -Name 'wuauserv'; \
             Get-Service -Name 'wuauserv' | Select-Object Name,Status"
        );
    }

    #[test]
    fn test_start_command_injection() {
        let cmd = WindowsServiceCommandBuilder::build_start_command("svc$(hostname)");
        assert!(cmd.contains("'svc$(hostname)'"));
    }

    // ── build_stop_command ──────────────────────────────────────────

    #[test]
    fn test_stop_command() {
        let cmd = WindowsServiceCommandBuilder::build_stop_command("wuauserv");
        assert_eq!(
            cmd,
            "Stop-Service -Name 'wuauserv' -Force; \
             Get-Service -Name 'wuauserv' | Select-Object Name,Status"
        );
    }

    #[test]
    fn test_stop_command_injection() {
        let cmd = WindowsServiceCommandBuilder::build_stop_command("svc|Out-File");
        assert!(cmd.contains("'svc|Out-File'"));
    }

    // ── build_restart_command ───────────────────────────────────────

    #[test]
    fn test_restart_command() {
        let cmd = WindowsServiceCommandBuilder::build_restart_command("wuauserv");
        assert_eq!(
            cmd,
            "Restart-Service -Name 'wuauserv' -Force; \
             Get-Service -Name 'wuauserv' | Select-Object Name,Status"
        );
    }

    #[test]
    fn test_restart_command_injection() {
        let cmd = WindowsServiceCommandBuilder::build_restart_command("svc`id`");
        assert!(cmd.contains("'svc`id`'"));
    }

    // ── build_list_command ──────────────────────────────────────────

    #[test]
    fn test_list_command() {
        let cmd = WindowsServiceCommandBuilder::build_list_command();
        assert_eq!(
            cmd,
            "Get-Service | Select-Object Name,DisplayName,Status,StartType \
             | Sort-Object Name | Format-Table -AutoSize"
        );
    }

    // ── build_enable_command ────────────────────────────────────────

    #[test]
    fn test_enable_command() {
        let cmd = WindowsServiceCommandBuilder::build_enable_command("wuauserv");
        assert_eq!(
            cmd,
            "Set-Service -Name 'wuauserv' -StartupType Automatic; \
             Get-Service -Name 'wuauserv' | Select-Object Name,StartType"
        );
    }

    #[test]
    fn test_enable_command_injection() {
        let cmd = WindowsServiceCommandBuilder::build_enable_command("svc; whoami");
        assert!(cmd.contains("'svc; whoami'"));
    }

    // ── build_disable_command ───────────────────────────────────────

    #[test]
    fn test_disable_command() {
        let cmd = WindowsServiceCommandBuilder::build_disable_command("wuauserv");
        assert_eq!(
            cmd,
            "Set-Service -Name 'wuauserv' -StartupType Disabled; \
             Get-Service -Name 'wuauserv' | Select-Object Name,StartType"
        );
    }

    #[test]
    fn test_disable_command_injection() {
        let cmd = WindowsServiceCommandBuilder::build_disable_command("svc$(hostname)");
        assert!(cmd.contains("'svc$(hostname)'"));
    }

    // ── build_config_command ────────────────────────────────────────

    #[test]
    fn test_config_command() {
        let cmd = WindowsServiceCommandBuilder::build_config_command("wuauserv");
        assert!(cmd.contains("Get-Service -Name 'wuauserv' | Select-Object *"));
        assert!(cmd.contains("Get-CimInstance Win32_Service -Filter \"Name='wuauserv'\""));
        assert!(cmd.contains("Select-Object PathName,StartMode,State,ProcessId"));
    }

    #[test]
    fn test_config_command_with_quote_in_name() {
        let cmd = WindowsServiceCommandBuilder::build_config_command("svc'test");
        // PowerShell escape doubles the single quote
        assert!(cmd.contains("'svc''test'"));
        // WMI filter also doubles the single quote
        assert!(cmd.contains("Name='svc''test'"));
    }

    #[test]
    fn test_config_command_injection() {
        let cmd = WindowsServiceCommandBuilder::build_config_command("svc; whoami");
        assert!(cmd.contains("'svc; whoami'"));
    }

    // ── build_event_logs_command ────────────────────────────────────

    #[test]
    fn test_event_logs_command() {
        let cmd = WindowsServiceCommandBuilder::build_event_logs_command("System", 50);
        assert_eq!(
            cmd,
            "Get-EventLog -LogName 'System' -Newest 50 | Format-Table -AutoSize"
        );
    }

    #[test]
    fn test_event_logs_command_application() {
        let cmd = WindowsServiceCommandBuilder::build_event_logs_command("Application", 100);
        assert!(cmd.contains("'Application'"));
        assert!(cmd.contains("-Newest 100"));
    }

    #[test]
    fn test_event_logs_command_injection() {
        let cmd =
            WindowsServiceCommandBuilder::build_event_logs_command("System; Remove-Item C:\\", 10);
        assert!(cmd.contains("'System; Remove-Item C:\\'"));
    }

    #[test]
    fn test_event_logs_command_zero_count() {
        let cmd = WindowsServiceCommandBuilder::build_event_logs_command("System", 0);
        assert!(cmd.contains("-Newest 0"));
    }

    #[test]
    fn test_event_logs_command_large_count() {
        let cmd = WindowsServiceCommandBuilder::build_event_logs_command("System", 1_000_000);
        assert!(cmd.contains("-Newest 1000000"));
    }

    // ── Shell Injection Prevention ──────────────────────────────────

    #[test]
    fn test_single_quote_escaping() {
        let cmd = WindowsServiceCommandBuilder::build_status_command("it's a service");
        // PowerShell escapes single quotes by doubling them
        assert!(cmd.contains("'it''s a service'"));
    }

    #[test]
    fn test_dollar_variable_neutralized() {
        let cmd = WindowsServiceCommandBuilder::build_start_command("$env:COMPUTERNAME");
        assert!(cmd.contains("'$env:COMPUTERNAME'"));
    }

    #[test]
    fn test_backtick_neutralized() {
        let cmd = WindowsServiceCommandBuilder::build_stop_command("svc`n");
        assert!(cmd.contains("'svc`n'"));
    }

    // ── validate_service_name Edge Cases ────────────────────────────

    #[test]
    fn test_validate_service_name_with_spaces() {
        assert!(validate_service_name("Windows Update").is_ok());
        assert!(validate_service_name("My Custom Service").is_ok());
    }

    #[test]
    fn test_validate_service_name_with_dots() {
        assert!(validate_service_name("svc.name.v2").is_ok());
    }

    #[test]
    fn test_validate_service_name_pipe_rejected() {
        assert!(validate_service_name("svc|bad").is_err());
    }

    #[test]
    fn test_validate_service_name_semicolon_rejected() {
        assert!(validate_service_name("svc;bad").is_err());
    }

    #[test]
    fn test_validate_service_name_ampersand_rejected() {
        assert!(validate_service_name("svc&bad").is_err());
    }
}
