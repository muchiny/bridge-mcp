//! Systemd Command Builder
//!
//! Builds `systemctl` and `journalctl` CLI commands for remote service
//! management via SSH. Supports status, start, stop, restart, list,
//! and log retrieval operations.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validates a service name to prevent command injection.
///
/// Service names must be alphanumeric with hyphens, underscores, dots, and `@`.
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
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@')
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid service name '{name}'. Only alphanumeric, hyphen, underscore, dot, and @ allowed.",
            ),
        })
    }
}

/// Builds systemd CLI commands for remote execution.
pub struct SystemdCommandBuilder;

impl SystemdCommandBuilder {
    /// Build a `systemctl status` command.
    ///
    /// Constructs: `systemctl status --no-pager -- {service}`
    #[must_use]
    pub fn build_status_command(service: &str) -> String {
        format!("systemctl status --no-pager -- {}", shell_escape(service))
    }

    /// Build a `systemctl start` command.
    ///
    /// Constructs: `systemctl start -- {service}`
    #[must_use]
    pub fn build_start_command(service: &str) -> String {
        format!("systemctl start -- {}", shell_escape(service))
    }

    /// Build a `systemctl stop` command.
    ///
    /// Constructs: `systemctl stop -- {service}`
    #[must_use]
    pub fn build_stop_command(service: &str) -> String {
        format!("systemctl stop -- {}", shell_escape(service))
    }

    /// Build a `systemctl restart` or `systemctl reload` command.
    ///
    /// Constructs: `systemctl {restart|reload|reload-or-restart} -- {service}`
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the action is not allowed.
    pub fn build_restart_command(service: &str, action: &str) -> Result<String> {
        Self::validate_restart_action(action)?;
        Ok(format!("systemctl {} -- {}", action, shell_escape(service)))
    }

    /// Validate a restart action.
    ///
    /// Only allows: `restart`, `reload`, `reload-or-restart`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the action is not allowed.
    pub fn validate_restart_action(action: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["restart", "reload", "reload-or-restart"];
        if ALLOWED.contains(&action) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Restart action '{}' is not allowed. Allowed actions: {}",
                    action,
                    ALLOWED.join(", ")
                ),
            })
        }
    }

    /// Build a `systemctl enable` command.
    ///
    /// Constructs: `systemctl enable -- {service}`
    #[must_use]
    pub fn build_enable_command(service: &str) -> String {
        format!("systemctl enable -- {}", shell_escape(service))
    }

    /// Build a `systemctl disable` command.
    ///
    /// Constructs: `systemctl disable -- {service}`
    #[must_use]
    pub fn build_disable_command(service: &str) -> String {
        format!("systemctl disable -- {}", shell_escape(service))
    }

    /// Build a `systemctl daemon-reload` command.
    ///
    /// Constructs: `systemctl daemon-reload`
    #[must_use]
    pub fn build_daemon_reload_command() -> String {
        "systemctl daemon-reload".to_string()
    }

    /// Build a `systemctl list-units` command.
    ///
    /// Constructs: `systemctl list-units --type=service [--state={s}]
    /// [--all] --no-pager --no-legend`
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `unit_type` is not in the allowlist.
    pub fn build_list_command(
        state: Option<&str>,
        all: bool,
        unit_type: Option<&str>,
    ) -> Result<String> {
        let utype = unit_type.unwrap_or("service");
        Self::validate_unit_type(utype)?;
        let mut cmd = format!("systemctl list-units --type={utype}");

        if let Some(s) = state {
            let _ = write!(cmd, " --state={}", shell_escape(s));
        }

        if all {
            cmd.push_str(" --all");
        }

        cmd.push_str(" --no-pager --no-legend");
        Ok(cmd)
    }

    /// Validate a systemd unit type against an allowlist.
    ///
    /// Allowed: `service`, `socket`, `timer`, `mount`, `target`, `automount`,
    /// `path`, `slice`, `scope`, `device`, `swap`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the unit type is not in the allowlist.
    fn validate_unit_type(t: &str) -> Result<()> {
        matches!(
            t,
            "service"
                | "socket"
                | "timer"
                | "mount"
                | "target"
                | "automount"
                | "path"
                | "slice"
                | "scope"
                | "device"
                | "swap"
        )
        .then_some(())
        .ok_or_else(|| BridgeError::CommandDenied {
            reason: format!(
                "Invalid systemd unit_type '{t}'. Allowed: service|socket|timer|mount|target|automount|path|slice|scope|device|swap"
            ),
        })
    }

    /// Build a `journalctl` command for service logs.
    ///
    /// Constructs: `journalctl -u {service} [--lines={N}] [--since={s}]
    /// [--until={u}] [--priority={p}] [--output={o}] [--reverse] --no-pager`
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_logs_command(
        service: &str,
        lines: Option<u64>,
        since: Option<&str>,
        until: Option<&str>,
        priority: Option<&str>,
        output: Option<&str>,
        reverse: bool,
    ) -> String {
        let mut cmd = format!("journalctl -u {}", shell_escape(service));

        if let Some(n) = lines {
            let _ = write!(cmd, " --lines={n}");
        }

        if let Some(s) = since {
            let _ = write!(cmd, " --since {}", shell_escape(s));
        }

        if let Some(u) = until {
            let _ = write!(cmd, " --until {}", shell_escape(u));
        }

        if let Some(p) = priority {
            let _ = write!(cmd, " --priority={}", shell_escape(p));
        }

        if let Some(o) = output {
            let _ = write!(cmd, " --output={}", shell_escape(o));
        }

        if reverse {
            cmd.push_str(" --reverse");
        }

        cmd.push_str(" --no-pager");
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_service_name ───────────────────────────────────────

    #[test]
    fn test_validate_service_name_valid() {
        assert!(validate_service_name("nginx").is_ok());
        assert!(validate_service_name("sshd.service").is_ok());
        assert!(validate_service_name("my-app_service").is_ok());
        assert!(validate_service_name("user@1000.service").is_ok());
    }

    #[test]
    fn test_validate_service_name_empty() {
        assert!(validate_service_name("").is_err());
    }

    #[test]
    fn test_validate_service_name_injection() {
        assert!(validate_service_name("nginx; rm -rf /").is_err());
        assert!(validate_service_name("nginx && cat /etc/shadow").is_err());
        assert!(validate_service_name("nginx$(whoami)").is_err());
    }

    // ── build_status_command ────────────────────────────────────────

    #[test]
    fn test_status_command() {
        let cmd = SystemdCommandBuilder::build_status_command("nginx");
        assert_eq!(cmd, "systemctl status --no-pager -- 'nginx'");
    }

    // ── build_start_command ─────────────────────────────────────────

    #[test]
    fn test_start_command() {
        let cmd = SystemdCommandBuilder::build_start_command("nginx");
        assert_eq!(cmd, "systemctl start -- 'nginx'");
    }

    // ── build_stop_command ──────────────────────────────────────────

    #[test]
    fn test_stop_command() {
        let cmd = SystemdCommandBuilder::build_stop_command("nginx");
        assert_eq!(cmd, "systemctl stop -- 'nginx'");
    }

    // ── build_restart_command ───────────────────────────────────────

    #[test]
    fn test_restart_command() {
        let cmd = SystemdCommandBuilder::build_restart_command("nginx", "restart").unwrap();
        assert_eq!(cmd, "systemctl restart -- 'nginx'");
    }

    #[test]
    fn test_reload_command() {
        let cmd = SystemdCommandBuilder::build_restart_command("nginx", "reload").unwrap();
        assert_eq!(cmd, "systemctl reload -- 'nginx'");
    }

    #[test]
    fn test_validate_restart_action_allowed() {
        assert!(SystemdCommandBuilder::validate_restart_action("restart").is_ok());
        assert!(SystemdCommandBuilder::validate_restart_action("reload").is_ok());
        assert!(SystemdCommandBuilder::validate_restart_action("reload-or-restart").is_ok());
    }

    #[test]
    fn test_validate_restart_action_denied() {
        assert!(SystemdCommandBuilder::validate_restart_action("start").is_err());
        assert!(SystemdCommandBuilder::validate_restart_action("stop").is_err());
        assert!(SystemdCommandBuilder::validate_restart_action("").is_err());
    }

    // ── build_list_command ──────────────────────────────────────────

    #[test]
    fn test_list_command_minimal() {
        let cmd = SystemdCommandBuilder::build_list_command(None, false, None).unwrap();
        assert_eq!(
            cmd,
            "systemctl list-units --type=service --no-pager --no-legend"
        );
    }

    #[test]
    fn test_list_command_with_state() {
        let cmd = SystemdCommandBuilder::build_list_command(Some("running"), false, None).unwrap();
        assert!(cmd.contains("--state='running'"));
    }

    #[test]
    fn test_list_command_all() {
        let cmd = SystemdCommandBuilder::build_list_command(None, true, None).unwrap();
        assert!(cmd.contains("--all"));
    }

    #[test]
    fn test_list_command_custom_type() {
        let cmd = SystemdCommandBuilder::build_list_command(None, false, Some("timer")).unwrap();
        assert!(cmd.contains("--type=timer"));
    }

    // ── build_logs_command ──────────────────────────────────────────

    #[test]
    fn test_logs_command_minimal() {
        let cmd =
            SystemdCommandBuilder::build_logs_command("nginx", None, None, None, None, None, false);
        assert_eq!(cmd, "journalctl -u 'nginx' --no-pager");
    }

    #[test]
    fn test_logs_command_with_lines() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "nginx",
            Some(100),
            None,
            None,
            None,
            None,
            false,
        );
        assert!(cmd.contains("--lines=100"));
    }

    #[test]
    fn test_logs_command_with_since() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "nginx",
            None,
            Some("1 hour ago"),
            None,
            None,
            None,
            false,
        );
        assert!(cmd.contains("--since '1 hour ago'"));
    }

    #[test]
    fn test_logs_command_with_priority() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "nginx",
            None,
            None,
            None,
            Some("err"),
            None,
            false,
        );
        assert!(cmd.contains("--priority='err'"));
    }

    #[test]
    fn test_logs_command_with_output_format() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "nginx",
            None,
            None,
            None,
            None,
            Some("json"),
            false,
        );
        assert!(cmd.contains("--output='json'"));
    }

    #[test]
    fn test_logs_command_reverse() {
        let cmd =
            SystemdCommandBuilder::build_logs_command("nginx", None, None, None, None, None, true);
        assert!(cmd.contains("--reverse"));
    }

    #[test]
    fn test_logs_command_all_options() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "sshd",
            Some(50),
            Some("today"),
            Some("now"),
            Some("warning"),
            Some("short-iso"),
            true,
        );
        assert!(cmd.starts_with("journalctl -u 'sshd'"));
        assert!(cmd.contains("--lines=50"));
        assert!(cmd.contains("--since 'today'"));
        assert!(cmd.contains("--until 'now'"));
        assert!(cmd.contains("--priority='warning'"));
        assert!(cmd.contains("--output='short-iso'"));
        assert!(cmd.contains("--reverse"));
        assert!(cmd.contains("--no-pager"));
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_restart_invalid_action_rejected() {
        let result = SystemdCommandBuilder::build_restart_command("nginx", "restart; rm -rf /");
        assert!(result.is_err());
    }

    #[test]
    fn test_status_injection_in_service() {
        let cmd = SystemdCommandBuilder::build_status_command("nginx; whoami");
        assert!(cmd.contains("systemctl status --no-pager -- 'nginx; whoami'"));
    }

    #[test]
    fn test_logs_injection_in_since() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "nginx",
            None,
            Some("today; rm -rf /"),
            None,
            None,
            None,
            false,
        );
        assert!(cmd.contains("--since 'today; rm -rf /'"));
    }

    #[test]
    fn test_logs_injection_in_priority() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "nginx",
            None,
            None,
            None,
            Some("err$(whoami)"),
            None,
            false,
        );
        assert!(cmd.contains("--priority='err$(whoami)'"));
    }

    #[test]
    fn test_list_injection_in_state() {
        let cmd = SystemdCommandBuilder::build_list_command(Some("running; whoami"), false, None)
            .unwrap();
        assert!(cmd.contains("--state='running; whoami'"));
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_list_all_options() {
        let cmd = SystemdCommandBuilder::build_list_command(Some("running"), true, Some("socket"))
            .unwrap();
        assert!(cmd.contains("--type=socket"));
        assert!(cmd.contains("--state='running'"));
        assert!(cmd.contains("--all"));
        assert!(cmd.contains("--no-pager --no-legend"));
    }

    #[test]
    fn test_reload_or_restart_action() {
        let cmd =
            SystemdCommandBuilder::build_restart_command("nginx", "reload-or-restart").unwrap();
        assert_eq!(cmd, "systemctl reload-or-restart -- 'nginx'");
    }

    // ============== validate_service_name Edge Cases ==============

    #[test]
    fn test_validate_service_name_template_instance() {
        assert!(validate_service_name("getty@tty1.service").is_ok());
    }

    #[test]
    fn test_validate_service_name_only_dot_service() {
        assert!(validate_service_name("a.service").is_ok());
    }

    #[test]
    fn test_validate_service_name_pipe_rejected() {
        assert!(validate_service_name("nginx|bad").is_err());
    }

    #[test]
    fn test_validate_service_name_backtick_rejected() {
        assert!(validate_service_name("nginx`id`").is_err());
    }

    #[test]
    fn test_validate_service_name_dollar_rejected() {
        assert!(validate_service_name("nginx$PATH").is_err());
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

    // ============== Logs Edge Cases ==============

    #[test]
    fn test_logs_with_until_only() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "nginx",
            None,
            None,
            Some("2024-01-01"),
            None,
            None,
            false,
        );
        assert!(cmd.contains("--until '2024-01-01'"));
        assert!(!cmd.contains("--since"));
    }

    #[test]
    fn test_logs_lines_zero() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "nginx",
            Some(0),
            None,
            None,
            None,
            None,
            false,
        );
        assert!(cmd.contains("--lines=0"));
    }

    #[test]
    fn test_logs_lines_large() {
        let cmd = SystemdCommandBuilder::build_logs_command(
            "nginx",
            Some(1_000_000),
            None,
            None,
            None,
            None,
            false,
        );
        assert!(cmd.contains("--lines=1000000"));
    }

    #[test]
    fn test_validate_restart_action_error_message() {
        let result = SystemdCommandBuilder::validate_restart_action("enable");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("enable"));
                assert!(reason.contains("not allowed"));
                assert!(reason.contains("restart"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ============== build_enable_command ==============

    #[test]
    fn test_enable_command() {
        let cmd = SystemdCommandBuilder::build_enable_command("nginx");
        assert_eq!(cmd, "systemctl enable -- 'nginx'");
    }

    #[test]
    fn test_enable_command_injection() {
        let cmd = SystemdCommandBuilder::build_enable_command("nginx; rm -rf /");
        assert!(cmd.contains("systemctl enable -- 'nginx; rm -rf /'"));
    }

    // ============== build_disable_command ==============

    #[test]
    fn test_disable_command() {
        let cmd = SystemdCommandBuilder::build_disable_command("nginx");
        assert_eq!(cmd, "systemctl disable -- 'nginx'");
    }

    #[test]
    fn test_disable_command_injection() {
        let cmd = SystemdCommandBuilder::build_disable_command("nginx$(whoami)");
        assert!(cmd.contains("systemctl disable -- 'nginx$(whoami)'"));
    }

    // ============== option-like unit names ==============

    #[test]
    fn test_unit_goes_after_double_dash() {
        // `-.mount` and `-.slice` are real units: `--` keeps them operands.
        for cmd in [
            SystemdCommandBuilder::build_status_command("-.mount"),
            SystemdCommandBuilder::build_start_command("-.mount"),
            SystemdCommandBuilder::build_stop_command("-.mount"),
            SystemdCommandBuilder::build_enable_command("-.mount"),
            SystemdCommandBuilder::build_disable_command("-.mount"),
            SystemdCommandBuilder::build_restart_command("-.mount", "restart").unwrap(),
        ] {
            assert!(cmd.contains(" -- '-.mount'"), "{cmd}");
        }
        let status = SystemdCommandBuilder::build_status_command("-.mount");
        assert!(status.ends_with(" -- '-.mount'"), "{status}");
    }

    // ============== build_daemon_reload_command ==============

    #[test]
    fn test_daemon_reload_command() {
        let cmd = SystemdCommandBuilder::build_daemon_reload_command();
        assert_eq!(cmd, "systemctl daemon-reload");
    }

    // ============== unit_type allowlist (Vuln 6) ==============

    #[test]
    fn test_list_command_rejects_injection_in_unit_type() {
        let r = SystemdCommandBuilder::build_list_command(
            None,
            false,
            Some("service; cat /etc/shadow #"),
        );
        assert!(
            r.is_err(),
            "must reject unit_type with shell metacharacters"
        );
    }

    #[test]
    fn test_list_command_accepts_known_unit_types() {
        for t in [
            "service",
            "socket",
            "timer",
            "mount",
            "target",
            "automount",
            "path",
            "slice",
            "scope",
            "device",
            "swap",
        ] {
            let r = SystemdCommandBuilder::build_list_command(None, false, Some(t));
            assert!(r.is_ok(), "{t} should be accepted");
        }
    }

    #[test]
    fn test_list_command_default_no_unit_type() {
        let r = SystemdCommandBuilder::build_list_command(None, false, None);
        assert!(r.is_ok());
        assert!(r.unwrap().contains("--type=service"));
    }
}
