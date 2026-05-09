//! Firewall Command Builder
//!
//! Builds firewall management CLI commands for remote execution via SSH.
//! Auto-detects the firewall tool: ufw, firewalld (firewall-cmd), or iptables.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Generate a firewall tool detection prefix.
#[must_use]
pub fn firewall_detect() -> String {
    "$(if command -v ufw &>/dev/null; then echo ufw; \
     elif command -v firewall-cmd &>/dev/null; then echo firewall-cmd; \
     elif command -v iptables &>/dev/null; then echo iptables; \
     elif [ -x /usr/sbin/iptables ]; then echo /usr/sbin/iptables; \
     else echo 'No firewall tool found on host' >&2; echo false; fi)"
        .to_string()
}

/// Validate that a port specification is valid.
/// Accepts: single port number (1-65535), port range (e.g., "8080:8090"),
/// or a service name (alphanumeric + hyphens only).
pub fn validate_port(port: &str) -> Result<()> {
    if port.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Port cannot be empty".to_string(),
        });
    }

    // Port range: "start:end"
    if let Some((start, end)) = port.split_once(':') {
        let s: u16 = start.parse().map_err(|_| BridgeError::CommandDenied {
            reason: format!("Invalid port range start: '{start}'"),
        })?;
        let e: u16 = end.parse().map_err(|_| BridgeError::CommandDenied {
            reason: format!("Invalid port range end: '{end}'"),
        })?;
        if s == 0 || e == 0 || s > e {
            return Err(BridgeError::CommandDenied {
                reason: format!("Invalid port range: {s}:{e}"),
            });
        }
        return Ok(());
    }

    // Single numeric port
    if let Ok(p) = port.parse::<u16>() {
        if p == 0 {
            return Err(BridgeError::CommandDenied {
                reason: "Port 0 is not valid".to_string(),
            });
        }
        return Ok(());
    }

    // If it looks numeric but didn't parse as u16, it's out of range
    if port.chars().all(|c| c.is_ascii_digit()) {
        return Err(BridgeError::CommandDenied {
            reason: format!("Invalid port number: '{port}' (must be 1-65535)"),
        });
    }

    // Service name (e.g., "http", "ssh"): alphanumeric + hyphens only
    if port.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Ok(());
    }

    Err(BridgeError::CommandDenied {
        reason: format!(
            "Invalid port: '{port}'. Expected a port number (1-65535), range (e.g., '8080:8090'), or service name"
        ),
    })
}

fn validate_protocol(p: &str) -> Result<()> {
    matches!(p, "tcp" | "udp" | "icmp" | "icmpv6")
        .then_some(())
        .ok_or_else(|| BridgeError::CommandDenied {
            reason: format!("Invalid firewall protocol '{p}'. Allowed: tcp|udp|icmp|icmpv6"),
        })
}

/// Validate that a source address looks like a valid IP or CIDR.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the source contains invalid characters.
pub fn validate_source(source: &str) -> Result<()> {
    if source.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Source address cannot be empty".to_string(),
        });
    }
    // Allow only: hex digits, dots, colons (IPv6), slashes (CIDR)
    if !source
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid source address '{source}': must be a valid IP or CIDR notation"
            ),
        });
    }
    Ok(())
}

/// Builds firewall management commands for remote execution.
pub struct FirewallCommandBuilder;

impl FirewallCommandBuilder {
    /// Build a command to show firewall status.
    ///
    /// Constructs tool-appropriate status command.
    #[must_use]
    pub fn build_status_command(firewall_tool: Option<&str>) -> String {
        match firewall_tool {
            Some("ufw") => String::from("ufw status verbose"),
            Some("firewall-cmd") => String::from("firewall-cmd --state && firewall-cmd --list-all"),
            Some("iptables") => String::from("iptables -L -n -v --line-numbers"),
            _ => String::from(
                "if command -v ufw &>/dev/null; then ufw status verbose; \
                 elif command -v firewall-cmd &>/dev/null; then firewall-cmd --state && firewall-cmd --list-all; \
                 elif command -v iptables &>/dev/null; then iptables -L -n -v --line-numbers; \
                 elif [ -x /usr/sbin/iptables ]; then /usr/sbin/iptables -L -n -v --line-numbers; \
                 else echo 'No firewall tool found'; exit 127; fi",
            ),
        }
    }

    /// Build a command to list firewall rules.
    ///
    /// Constructs tool-appropriate rule listing command.
    #[must_use]
    pub fn build_list_command(firewall_tool: Option<&str>, chain: Option<&str>) -> String {
        match firewall_tool {
            Some("ufw") => String::from("ufw status numbered"),
            Some("firewall-cmd") => String::from("firewall-cmd --list-all --zone=public"),
            Some("iptables") => {
                let mut cmd = String::from("iptables -L -n -v --line-numbers");
                if let Some(c) = chain {
                    cmd = format!("iptables -L {} -n -v --line-numbers", shell_escape(c));
                }
                cmd
            }
            _ => String::from(
                "if command -v ufw &>/dev/null; then ufw status numbered; \
                 elif command -v firewall-cmd &>/dev/null; then firewall-cmd --list-all --zone=public; \
                 elif command -v iptables &>/dev/null; then iptables -L -n -v --line-numbers; \
                 elif [ -x /usr/sbin/iptables ]; then /usr/sbin/iptables -L -n -v --line-numbers; \
                 else echo 'No firewall tool found'; exit 127; fi",
            ),
        }
    }

    /// Build a command to allow a port/service.
    ///
    /// Constructs tool-appropriate allow rule. Validates port and source before
    /// building the command.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if port or source is invalid.
    pub fn build_allow_command(
        firewall_tool: Option<&str>,
        port: &str,
        protocol: Option<&str>,
        source: Option<&str>,
    ) -> Result<String> {
        validate_port(port)?;
        if let Some(p) = protocol {
            validate_protocol(p)?;
        }
        if let Some(src) = source {
            validate_source(src)?;
        }
        let proto = protocol.unwrap_or("tcp");
        Ok(match firewall_tool {
            Some("ufw") => {
                if let Some(src) = source {
                    format!(
                        "ufw allow from {} to any port {} proto {}",
                        shell_escape(src),
                        shell_escape(port),
                        proto
                    )
                } else {
                    format!("ufw allow {}/{}", shell_escape(port), proto)
                }
            }
            Some("firewall-cmd") => {
                let mut cmd = format!(
                    "firewall-cmd --permanent --add-port={}/{}",
                    shell_escape(port),
                    proto
                );
                if let Some(src) = source {
                    let _ = write!(
                        cmd,
                        " && firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address={} port port={} protocol={} accept'",
                        shell_escape(src),
                        shell_escape(port),
                        proto
                    );
                }
                cmd.push_str(" && firewall-cmd --reload");
                cmd
            }
            Some("iptables") => {
                let mut cmd = format!(
                    "iptables -A INPUT -p {} --dport {}",
                    proto,
                    shell_escape(port)
                );
                if let Some(src) = source {
                    let _ = write!(cmd, " -s {}", shell_escape(src));
                }
                cmd.push_str(" -j ACCEPT");
                cmd
            }
            _ => {
                let escaped_port = shell_escape(port);
                format!(
                    "if command -v ufw &>/dev/null; then ufw allow {escaped_port}/{proto}; \
                     elif command -v firewall-cmd &>/dev/null; then firewall-cmd --permanent --add-port={escaped_port}/{proto} && firewall-cmd --reload; \
                     elif command -v iptables &>/dev/null; then iptables -A INPUT -p {proto} --dport {escaped_port} -j ACCEPT; \
                     elif [ -x /usr/sbin/iptables ]; then /usr/sbin/iptables -A INPUT -p {proto} --dport {escaped_port} -j ACCEPT; \
                     else echo 'No firewall tool found'; exit 127; fi"
                )
            }
        })
    }

    /// Build a command to deny/block a port or source.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if port or source is invalid.
    pub fn build_deny_command(
        firewall_tool: Option<&str>,
        port: &str,
        protocol: Option<&str>,
        source: Option<&str>,
    ) -> Result<String> {
        validate_port(port)?;
        if let Some(p) = protocol {
            validate_protocol(p)?;
        }
        if let Some(src) = source {
            validate_source(src)?;
        }
        let proto = protocol.unwrap_or("tcp");
        Ok(match firewall_tool {
            Some("ufw") => {
                if let Some(src) = source {
                    format!(
                        "ufw deny from {} to any port {} proto {}",
                        shell_escape(src),
                        shell_escape(port),
                        proto
                    )
                } else {
                    format!("ufw deny {}/{}", shell_escape(port), proto)
                }
            }
            Some("firewall-cmd") => {
                let escaped_port = shell_escape(port);
                let mut cmd = if let Some(src) = source {
                    format!(
                        "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address={} port port={} protocol={} reject'",
                        shell_escape(src),
                        escaped_port,
                        proto
                    )
                } else {
                    format!(
                        "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 port port={escaped_port} protocol={proto} reject'"
                    )
                };
                cmd.push_str(" && firewall-cmd --reload");
                cmd
            }
            Some("iptables") => {
                let mut cmd = format!(
                    "iptables -A INPUT -p {} --dport {}",
                    proto,
                    shell_escape(port)
                );
                if let Some(src) = source {
                    let _ = write!(cmd, " -s {}", shell_escape(src));
                }
                cmd.push_str(" -j DROP");
                cmd
            }
            _ => {
                let escaped_port = shell_escape(port);
                format!(
                    "if command -v ufw &>/dev/null; then ufw deny {escaped_port}/{proto}; \
                     elif command -v firewall-cmd &>/dev/null; then firewall-cmd --permanent --add-rich-rule='rule family=ipv4 port port={escaped_port} protocol={proto} reject' && firewall-cmd --reload; \
                     elif command -v iptables &>/dev/null; then iptables -A INPUT -p {proto} --dport {escaped_port} -j DROP; \
                     elif [ -x /usr/sbin/iptables ]; then /usr/sbin/iptables -A INPUT -p {proto} --dport {escaped_port} -j DROP; \
                     else echo 'No firewall tool found'; exit 127; fi"
                )
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_ufw() {
        let cmd = FirewallCommandBuilder::build_status_command(Some("ufw"));
        assert_eq!(cmd, "ufw status verbose");
    }

    #[test]
    fn test_status_firewalld() {
        let cmd = FirewallCommandBuilder::build_status_command(Some("firewall-cmd"));
        assert!(cmd.contains("firewall-cmd --state"));
    }

    #[test]
    fn test_status_iptables() {
        let cmd = FirewallCommandBuilder::build_status_command(Some("iptables"));
        assert!(cmd.contains("iptables -L -n -v"));
    }

    #[test]
    fn test_status_auto() {
        let cmd = FirewallCommandBuilder::build_status_command(None);
        assert!(cmd.contains("command -v ufw"));
    }

    #[test]
    fn test_list_ufw() {
        let cmd = FirewallCommandBuilder::build_list_command(Some("ufw"), None);
        assert_eq!(cmd, "ufw status numbered");
    }

    #[test]
    fn test_list_iptables_chain() {
        let cmd = FirewallCommandBuilder::build_list_command(Some("iptables"), Some("INPUT"));
        assert!(cmd.contains("-L 'INPUT'"));
    }

    #[test]
    fn test_allow_ufw() {
        let cmd =
            FirewallCommandBuilder::build_allow_command(Some("ufw"), "443", None, None).unwrap();
        assert_eq!(cmd, "ufw allow '443'/tcp");
    }

    #[test]
    fn test_allow_ufw_with_source() {
        let cmd = FirewallCommandBuilder::build_allow_command(
            Some("ufw"),
            "22",
            Some("tcp"),
            Some("10.0.0.0/8"),
        )
        .unwrap();
        assert!(cmd.contains("from '10.0.0.0/8'"));
    }

    #[test]
    fn test_deny_iptables() {
        let cmd =
            FirewallCommandBuilder::build_deny_command(Some("iptables"), "80", None, None).unwrap();
        assert!(cmd.contains("-j DROP"));
        assert!(cmd.contains("--dport '80'"));
    }

    #[test]
    fn test_allow_auto() {
        let cmd = FirewallCommandBuilder::build_allow_command(None, "80", None, None).unwrap();
        assert!(cmd.contains("ufw allow"));
        assert!(cmd.contains("firewall-cmd"));
        assert!(cmd.contains("iptables"));
    }

    // ── validate_port ─────────────────────────────────────────────

    #[test]
    fn test_validate_port_valid() {
        assert!(validate_port("80").is_ok());
        assert!(validate_port("443").is_ok());
        assert!(validate_port("8080:8090").is_ok());
        assert!(validate_port("http").is_ok());
        assert!(validate_port("ssh").is_ok());
    }

    #[test]
    fn test_validate_port_invalid() {
        assert!(validate_port("").is_err());
        assert!(validate_port("0").is_err());
        assert!(validate_port("80; rm -rf /").is_err());
        assert!(validate_port("99999").is_err()); // > 65535 can't parse as u16
    }

    #[test]
    fn test_validate_port_range_invalid() {
        assert!(validate_port("8090:8080").is_err()); // end < start
        assert!(validate_port("0:80").is_err()); // start is 0
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_allow_injection_in_source_rejected() {
        let result = FirewallCommandBuilder::build_allow_command(
            Some("ufw"),
            "22",
            None,
            Some("10.0.0.1; rm -rf /"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_deny_injection_in_source_rejected() {
        let result = FirewallCommandBuilder::build_deny_command(
            Some("iptables"),
            "80",
            None,
            Some("$(whoami)"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_source_valid() {
        assert!(validate_source("10.0.0.1").is_ok());
        assert!(validate_source("192.168.1.0/24").is_ok());
        assert!(validate_source("::1").is_ok());
        assert!(validate_source("fe80::1").is_ok());
    }

    #[test]
    fn test_validate_source_invalid() {
        assert!(validate_source("").is_err());
        assert!(validate_source("10.0.0.1; whoami").is_err());
        assert!(validate_source("$(evil)").is_err());
        assert!(validate_source("host name").is_err());
    }

    #[test]
    fn test_list_injection_in_chain() {
        let cmd =
            FirewallCommandBuilder::build_list_command(Some("iptables"), Some("INPUT; whoami"));
        assert!(cmd.contains("-L 'INPUT; whoami'"));
    }

    // ============== firewall_detect ==============

    #[test]
    fn test_firewall_detect_contains_all_tools() {
        let detect = firewall_detect();
        assert!(detect.contains("command -v ufw"));
        assert!(detect.contains("command -v firewall-cmd"));
        assert!(detect.contains("command -v iptables"));
        // When no firewall tool is found we emit a stderr message and echo
        // `false` so the outer command fails with exit 1 instead of running
        // a literal sentinel as a command (exit 127, confusing).
        assert!(detect.contains("No firewall tool found"));
        assert!(detect.contains("echo false"));
    }

    #[test]
    fn test_firewall_detect_includes_sbin_fallback() {
        let detect = firewall_detect();
        assert!(detect.contains("/usr/sbin/iptables"));
    }

    #[test]
    fn test_status_auto_detect_includes_sbin_fallback() {
        let cmd = FirewallCommandBuilder::build_status_command(None);
        assert!(cmd.contains("/usr/sbin/iptables"));
    }

    #[test]
    fn test_list_auto_detect_includes_sbin_fallback() {
        let cmd = FirewallCommandBuilder::build_list_command(None, None);
        assert!(cmd.contains("/usr/sbin/iptables"));
    }

    #[test]
    fn test_allow_auto_detect_includes_sbin_fallback() {
        let cmd = FirewallCommandBuilder::build_allow_command(None, "443", None, None).unwrap();
        assert!(cmd.contains("/usr/sbin/iptables"));
    }

    #[test]
    fn test_deny_auto_detect_includes_sbin_fallback() {
        let cmd = FirewallCommandBuilder::build_deny_command(None, "443", None, None).unwrap();
        assert!(cmd.contains("/usr/sbin/iptables"));
    }

    // ============== Deny Command Variants ==============

    #[test]
    fn test_deny_ufw() {
        let cmd =
            FirewallCommandBuilder::build_deny_command(Some("ufw"), "443", None, None).unwrap();
        assert!(cmd.contains("ufw deny '443'/tcp"));
    }

    #[test]
    fn test_deny_ufw_with_source() {
        let cmd = FirewallCommandBuilder::build_deny_command(
            Some("ufw"),
            "22",
            Some("tcp"),
            Some("10.0.0.0/8"),
        )
        .unwrap();
        assert!(cmd.contains("ufw deny from '10.0.0.0/8'"));
        assert!(cmd.contains("port '22'"));
    }

    #[test]
    fn test_deny_firewalld() {
        let cmd =
            FirewallCommandBuilder::build_deny_command(Some("firewall-cmd"), "80", None, None)
                .unwrap();
        assert!(cmd.contains("--add-rich-rule="));
        assert!(cmd.contains("reject"));
        assert!(cmd.contains("--reload"));
    }

    #[test]
    fn test_deny_firewalld_with_source() {
        let cmd = FirewallCommandBuilder::build_deny_command(
            Some("firewall-cmd"),
            "80",
            None,
            Some("192.168.1.0/24"),
        )
        .unwrap();
        assert!(cmd.contains("source address='192.168.1.0/24'"));
        assert!(cmd.contains("reject"));
    }

    #[test]
    fn test_deny_iptables_with_source() {
        let cmd = FirewallCommandBuilder::build_deny_command(
            Some("iptables"),
            "80",
            None,
            Some("10.0.0.5"),
        )
        .unwrap();
        assert!(cmd.contains("-s '10.0.0.5'"));
        assert!(cmd.contains("-j DROP"));
    }

    #[test]
    fn test_deny_auto_detect() {
        let cmd = FirewallCommandBuilder::build_deny_command(None, "443", None, None).unwrap();
        assert!(cmd.contains("ufw deny"));
        assert!(cmd.contains("firewall-cmd"));
        assert!(cmd.contains("iptables"));
        assert!(cmd.contains("-j DROP"));
    }

    // ============== Allow Command Variants ==============

    #[test]
    fn test_allow_firewalld() {
        let cmd =
            FirewallCommandBuilder::build_allow_command(Some("firewall-cmd"), "443", None, None)
                .unwrap();
        assert!(cmd.contains("--permanent --add-port='443'/tcp"));
        assert!(cmd.contains("--reload"));
    }

    #[test]
    fn test_allow_iptables() {
        let cmd = FirewallCommandBuilder::build_allow_command(Some("iptables"), "80", None, None)
            .unwrap();
        assert!(cmd.contains("iptables -A INPUT -p tcp --dport '80'"));
        assert!(cmd.contains("-j ACCEPT"));
    }

    #[test]
    fn test_allow_iptables_with_source() {
        let cmd = FirewallCommandBuilder::build_allow_command(
            Some("iptables"),
            "22",
            None,
            Some("192.168.1.0/24"),
        )
        .unwrap();
        assert!(cmd.contains("-s '192.168.1.0/24'"));
        assert!(cmd.contains("-j ACCEPT"));
    }

    // ============== Protocol Variants ==============

    #[test]
    fn test_allow_ufw_udp() {
        let cmd = FirewallCommandBuilder::build_allow_command(Some("ufw"), "53", Some("udp"), None)
            .unwrap();
        assert!(cmd.contains("'53'/udp"));
    }

    #[test]
    fn test_deny_iptables_udp() {
        let cmd =
            FirewallCommandBuilder::build_deny_command(Some("iptables"), "53", Some("udp"), None)
                .unwrap();
        assert!(cmd.contains("-p udp"));
        assert!(cmd.contains("-j DROP"));
    }

    // ============== validate_port Additional Tests ==============

    #[test]
    fn test_validate_port_max_value() {
        assert!(validate_port("65535").is_ok());
    }

    #[test]
    fn test_validate_port_one() {
        assert!(validate_port("1").is_ok());
    }

    #[test]
    fn test_validate_port_range_same_start_end() {
        assert!(validate_port("80:80").is_ok());
    }

    #[test]
    fn test_validate_port_service_with_hyphens() {
        assert!(validate_port("my-custom-service").is_ok());
    }

    // ============== Protocol Injection Prevention (Vuln 7) ==============

    #[test]
    fn test_allow_rejects_protocol_injection() {
        let r = FirewallCommandBuilder::build_allow_command(
            None,
            "80",
            Some("tcp -j ACCEPT; nc -e /bin/sh evil 9; iptables -A INPUT -p tcp"),
            None,
        );
        assert!(r.is_err(), "must reject injection in protocol");
    }

    #[test]
    fn test_deny_rejects_protocol_injection() {
        let r = FirewallCommandBuilder::build_deny_command(
            None,
            "80",
            Some("udp; rm -rf /"),
            None,
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_allow_accepts_known_protocols() {
        for p in ["tcp", "udp", "icmp", "icmpv6"] {
            let r = FirewallCommandBuilder::build_allow_command(Some("ufw"), "80", Some(p), None);
            assert!(r.is_ok(), "{p} should be accepted");
        }
    }

    #[test]
    fn test_allow_rejects_unknown_protocol() {
        let r = FirewallCommandBuilder::build_allow_command(Some("ufw"), "80", Some("sctp"), None);
        assert!(r.is_err(), "sctp is not in the allowlist");
    }
}
