//! Network Security Command Builder
//!
//! Builds network security analysis CLI commands for remote execution via SSH.
//! Supports port scanning, SSL/TLS auditing, network traffic capture,
//! and fail2ban status inspection.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a port number is within the valid range (1-65535).
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the port is 0 or exceeds 65535.
pub fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(BridgeError::CommandDenied {
            reason: "Port number must be between 1 and 65535".to_string(),
        });
    }
    Ok(())
}

/// Validate that the capture count does not exceed the maximum (1000).
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if count exceeds 1000.
pub fn validate_capture_count(count: u32) -> Result<()> {
    if count == 0 || count > 1000 {
        return Err(BridgeError::CommandDenied {
            reason: format!("Capture count must be between 1 and 1000, got {count}"),
        });
    }
    Ok(())
}

/// Validate that a target string is safe for shell use (no injection).
///
/// A valid target should only contain alphanumeric characters, dots, hyphens,
/// colons (IPv6), slashes (CIDR), and underscores.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the target is empty, starts with
/// `-` (a scanner would read it as an option such as `-oN<file>`) or contains
/// shell-dangerous characters.
pub fn validate_target(target: &str) -> Result<()> {
    if target.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Target cannot be empty".to_string(),
        });
    }
    super::shell::refuse_option_like("target", target)?;
    if !target
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '/' | '_'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid target '{target}': must contain only alphanumeric characters, \
                 dots, hyphens, colons, or slashes"
            ),
        });
    }
    Ok(())
}

/// Builds network security analysis commands for remote execution.
pub struct NetworkSecurityCommandBuilder;

impl NetworkSecurityCommandBuilder {
    /// Build a command to scan for open ports.
    ///
    /// For local scanning (no target or target is "localhost"/"127.0.0.1"):
    ///   `ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null`
    ///
    /// For remote targets:
    ///   `nmap -sT TARGET -p PORTS 2>/dev/null || for p in PORTS; do ...`
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the target is invalid.
    #[must_use]
    pub fn build_port_scan_command(target: Option<&str>, ports: Option<&str>) -> String {
        let is_local = match target {
            None => true,
            Some(t) => t == "localhost" || t == "127.0.0.1" || t == "::1",
        };

        if is_local {
            return String::from("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null");
        }

        let target_str = target.unwrap_or("localhost");
        let escaped_target = shell_escape(target_str);
        let port_spec = ports.unwrap_or("22,80,443,8080,8443,3306,5432,6379,27017");
        let escaped_ports = shell_escape(port_spec);

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "nmap -sT {escaped_target} -p {escaped_ports} 2>/dev/null || \
             for p in $(printf '%s' {escaped_ports} | tr ',' ' '); do \
             (echo >/dev/tcp/{target_str}/$p) 2>/dev/null && \
             echo \"port $p open\"; done"
        );
        cmd
    }

    /// Build a command to audit SSL/TLS certificates and configuration.
    ///
    /// Constructs: `echo | openssl s_client -connect HOST:PORT -servername HOST 2>/dev/null
    ///              | openssl x509 -noout -text 2>/dev/null`
    #[must_use]
    pub fn build_ssl_audit_command(host: &str, port: u16) -> String {
        let escaped_host = shell_escape(host);
        format!(
            "echo | openssl s_client -connect {escaped_host}:{port} \
             -servername {escaped_host} 2>/dev/null | \
             openssl x509 -noout -text 2>/dev/null"
        )
    }

    /// Build a command to capture network traffic.
    ///
    /// Constructs: `tcpdump -i IFACE -c COUNT -nn [-- FILTER] 2>&1`
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the count exceeds 1000.
    pub fn build_network_capture_command(
        interface: Option<&str>,
        filter: Option<&str>,
        count: u32,
    ) -> Result<String> {
        validate_capture_count(count)?;

        let iface = interface.unwrap_or("any");
        let escaped_iface = shell_escape(iface);

        let mut cmd = format!("tcpdump -i {escaped_iface} -c {count} -nn");

        // `--` first: `-w<file>` in the filter would make tcpdump write a file.
        if let Some(f) = filter {
            let _ = write!(cmd, " -- {}", shell_escape(f));
        }

        cmd.push_str(" 2>&1");
        Ok(cmd)
    }

    /// Build a command to check fail2ban status.
    ///
    /// Constructs: `fail2ban-client status [JAIL] 2>/dev/null || echo 'fail2ban not available'`
    #[must_use]
    pub fn build_fail2ban_status_command(jail: Option<&str>) -> String {
        let mut cmd = String::from("fail2ban-client status");

        if let Some(j) = jail {
            let _ = write!(cmd, " {}", shell_escape(j));
        }

        cmd.push_str(" 2>/dev/null || echo 'fail2ban not available'");
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_port ─────────────────────────────────────

    #[test]
    fn test_validate_port_valid() {
        assert!(validate_port(1).is_ok());
        assert!(validate_port(80).is_ok());
        assert!(validate_port(443).is_ok());
        assert!(validate_port(65535).is_ok());
    }

    #[test]
    fn test_validate_port_zero() {
        assert!(validate_port(0).is_err());
    }

    // ── validate_capture_count ────────────────────────────

    #[test]
    fn test_validate_capture_count_valid() {
        assert!(validate_capture_count(1).is_ok());
        assert!(validate_capture_count(100).is_ok());
        assert!(validate_capture_count(1000).is_ok());
    }

    #[test]
    fn test_validate_capture_count_zero() {
        assert!(validate_capture_count(0).is_err());
    }

    #[test]
    fn test_validate_capture_count_exceeds_max() {
        assert!(validate_capture_count(1001).is_err());
    }

    #[test]
    fn test_validate_capture_count_error_message() {
        let result = validate_capture_count(2000);
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("2000"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── validate_target ───────────────────────────────────

    #[test]
    fn test_validate_target_valid() {
        assert!(validate_target("192.168.1.1").is_ok());
        assert!(validate_target("example.com").is_ok());
        assert!(validate_target("my-host").is_ok());
        assert!(validate_target("::1").is_ok());
        assert!(validate_target("10.0.0.0/24").is_ok());
    }

    #[test]
    fn test_validate_target_empty() {
        assert!(validate_target("").is_err());
    }

    #[test]
    fn test_validate_target_injection() {
        assert!(validate_target("host; rm -rf /").is_err());
        assert!(validate_target("$(whoami)").is_err());
        assert!(validate_target("host`id`").is_err());
    }

    #[test]
    fn test_validate_target_refuses_leading_dash() {
        for bad in ["-oN/home/u/.bashrc", "-iL/etc/passwd", "-"] {
            let err = validate_target(bad).unwrap_err();
            assert!(
                err.to_string().contains("'target' must not start with '-'"),
                "{err}"
            );
        }
    }

    #[test]
    fn test_port_scan_ports_are_printed_with_a_format() {
        let cmd =
            NetworkSecurityCommandBuilder::build_port_scan_command(Some("10.0.0.1"), Some("-1000"));
        assert!(cmd.contains("printf '%s' '-1000' | tr"), "{cmd}");
        assert!(!cmd.contains("echo '-1000'"), "{cmd}");
    }

    // ── build_port_scan_command ───────────────────────────

    #[test]
    fn test_port_scan_local() {
        let cmd = NetworkSecurityCommandBuilder::build_port_scan_command(None, None);
        assert!(cmd.contains("ss -tlnp"));
        assert!(cmd.contains("netstat -tlnp"));
    }

    #[test]
    fn test_port_scan_localhost() {
        let cmd = NetworkSecurityCommandBuilder::build_port_scan_command(Some("localhost"), None);
        assert!(cmd.contains("ss -tlnp"));
    }

    #[test]
    fn test_port_scan_remote() {
        let cmd = NetworkSecurityCommandBuilder::build_port_scan_command(Some("192.168.1.1"), None);
        assert!(cmd.contains("nmap"));
        assert!(cmd.contains("192.168.1.1"));
    }

    #[test]
    fn test_port_scan_custom_ports() {
        let cmd = NetworkSecurityCommandBuilder::build_port_scan_command(
            Some("10.0.0.1"),
            Some("22,80,443"),
        );
        assert!(cmd.contains("22,80,443"));
    }

    #[test]
    fn test_port_scan_127_local() {
        let cmd = NetworkSecurityCommandBuilder::build_port_scan_command(Some("127.0.0.1"), None);
        assert!(cmd.contains("ss -tlnp"));
    }

    // ── build_ssl_audit_command ───────────────────────────

    #[test]
    fn test_ssl_audit_basic() {
        let cmd = NetworkSecurityCommandBuilder::build_ssl_audit_command("example.com", 443);
        assert!(cmd.contains("openssl s_client"));
        assert!(cmd.contains("example.com"));
        assert!(cmd.contains(":443"));
        assert!(cmd.contains("-servername"));
        assert!(cmd.contains("x509 -noout -text"));
    }

    #[test]
    fn test_ssl_audit_custom_port() {
        let cmd = NetworkSecurityCommandBuilder::build_ssl_audit_command("host.local", 8443);
        assert!(cmd.contains(":8443"));
    }

    // ── build_network_capture_command ─────────────────────

    #[test]
    fn test_capture_default() {
        let cmd =
            NetworkSecurityCommandBuilder::build_network_capture_command(None, None, 100).unwrap();
        assert!(cmd.contains("tcpdump"));
        assert!(cmd.contains("-c 100"));
        assert!(cmd.contains("-nn"));
        assert!(cmd.contains("'any'"));
    }

    #[test]
    fn test_capture_with_interface() {
        let cmd =
            NetworkSecurityCommandBuilder::build_network_capture_command(Some("eth0"), None, 50)
                .unwrap();
        assert!(cmd.contains("'eth0'"));
        assert!(cmd.contains("-c 50"));
    }

    #[test]
    fn test_capture_with_filter() {
        let cmd =
            NetworkSecurityCommandBuilder::build_network_capture_command(None, Some("port 80"), 10)
                .unwrap();
        assert!(cmd.contains("'port 80'"));
    }

    #[test]
    fn test_capture_filter_goes_after_double_dash() {
        let cmd = NetworkSecurityCommandBuilder::build_network_capture_command(
            None,
            Some("-w/etc/cron.d/x"),
            10,
        )
        .unwrap();
        assert_eq!(cmd, "tcpdump -i 'any' -c 10 -nn -- '-w/etc/cron.d/x' 2>&1");
    }

    #[test]
    fn test_capture_exceeds_max() {
        let result = NetworkSecurityCommandBuilder::build_network_capture_command(None, None, 1001);
        assert!(result.is_err());
    }

    #[test]
    fn test_capture_zero_count() {
        let result = NetworkSecurityCommandBuilder::build_network_capture_command(None, None, 0);
        assert!(result.is_err());
    }

    // ── build_fail2ban_status_command ─────────────────────

    #[test]
    fn test_fail2ban_status_default() {
        let cmd = NetworkSecurityCommandBuilder::build_fail2ban_status_command(None);
        assert!(cmd.contains("fail2ban-client status"));
        assert!(cmd.contains("fail2ban not available"));
    }

    #[test]
    fn test_fail2ban_status_with_jail() {
        let cmd = NetworkSecurityCommandBuilder::build_fail2ban_status_command(Some("sshd"));
        assert!(cmd.contains("fail2ban-client status 'sshd'"));
    }

    #[test]
    fn test_fail2ban_injection_in_jail() {
        let cmd = NetworkSecurityCommandBuilder::build_fail2ban_status_command(Some(
            "sshd; cat /etc/shadow",
        ));
        assert!(cmd.contains("'sshd; cat /etc/shadow'"));
    }

    // ── Shell injection prevention ────────────────────────

    #[test]
    fn test_ssl_audit_injection_in_host() {
        let cmd = NetworkSecurityCommandBuilder::build_ssl_audit_command("host$(id)", 443);
        // validate_target would catch this, but shell_escape also protects
        assert!(cmd.contains("'host$(id)'"));
    }

    #[test]
    fn test_capture_injection_in_interface() {
        let cmd = NetworkSecurityCommandBuilder::build_network_capture_command(
            Some("eth0; rm -rf /"),
            None,
            10,
        )
        .unwrap();
        assert!(cmd.contains("'eth0; rm -rf /'"));
    }
}
