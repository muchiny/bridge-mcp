//! Network Command Builder
//!
//! Builds network diagnostic CLI commands for remote execution via SSH.
//! Supports connection listing, interface info, routing, ping, traceroute,
//! and DNS lookup.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a network target is a plausible hostname or IP address.
/// Rejects empty strings and strings with shell-dangerous characters that,
/// while escaped, indicate misuse rather than legitimate targets.
pub fn validate_network_target(target: &str) -> Result<()> {
    if target.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Network target cannot be empty".to_string(),
        });
    }
    // A leading hyphen makes the word an OPTION to ping/traceroute/dig, not a
    // host — and shell-escaping cannot help, because the escape only decides
    // where the word ends, not how the program reads it. `dig '-f/etc/passwd'`
    // is one shell word and still turns a DNS lookup into a file read. No
    // hostname or IP starts with a hyphen, so refusing it costs nothing.
    if target.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid network target '{target}': a leading hyphen makes it an option to the \
                 diagnostic tool rather than a host."
            ),
        });
    }
    // A valid hostname/IP should only contain: alphanumeric, dots, hyphens, colons (IPv6), slashes (CIDR)
    if !target
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '/' | '_'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid network target '{target}': must contain only alphanumeric characters, dots, hyphens, colons, or slashes"
            ),
        });
    }
    Ok(())
}

/// Validate a network interface name.
///
/// Interface names are short and boring — `eth0`, `wlan0`, `br-1a2b`,
/// `enp3s0`, `eth0.100`, `veth@if4`. This had no validator at all: `interface`
/// went straight into `ping -I {}` behind a shell escape, which puts it in
/// option position.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the name is empty, over-long, or
/// carries anything but the characters interface names use.
pub fn validate_interface(interface: &str) -> Result<()> {
    if interface.is_empty() || interface.len() > 32 {
        return Err(BridgeError::CommandDenied {
            reason: format!("Invalid interface '{interface}': expected 1 to 32 characters"),
        });
    }
    if !interface.chars().next().is_some_and(char::is_alphanumeric) {
        return Err(BridgeError::CommandDenied {
            reason: format!("Invalid interface '{interface}': must start with a letter or digit"),
        });
    }
    if !interface
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '@'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid interface '{interface}': only alphanumerics, dot, hyphen, underscore, \
                 colon and at-sign are allowed"
            ),
        });
    }
    Ok(())
}

/// Validate a DNS record type.
///
/// `A`, `AAAA`, `MX`, `TXT`, `CNAME`, `SRV`, `CAA`, `TYPE65`… all letters and
/// digits, none longer than a dozen characters. Anything else in this slot is
/// read by `dig` as an option: `+short` is benign, `-f<file>` is not.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the type is empty, over-long, or
/// not alphanumeric.
pub fn validate_record_type(record_type: &str) -> Result<()> {
    if record_type.is_empty()
        || record_type.len() > 12
        || !record_type.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid DNS record type '{record_type}': expected a short alphanumeric type \
                 such as A, AAAA, MX or TXT"
            ),
        });
    }
    Ok(())
}

/// Builds network diagnostic commands for remote execution.
pub struct NetworkCommandBuilder;

impl NetworkCommandBuilder {
    /// Build a command to list active network connections.
    ///
    /// Constructs: `ss -tunap [--state {state}]` or filters by protocol.
    #[must_use]
    pub fn build_connections_command(
        protocol: Option<&str>,
        state: Option<&str>,
        listening: bool,
    ) -> String {
        let mut cmd = String::from("ss -tunap");

        if listening {
            cmd = String::from("ss -tlnp");
        }

        if let Some(proto) = protocol {
            match proto {
                "tcp" => {
                    cmd = if listening {
                        String::from("ss -tlnp")
                    } else {
                        String::from("ss -tnap")
                    };
                }
                "udp" => {
                    cmd = if listening {
                        String::from("ss -ulnp")
                    } else {
                        String::from("ss -unap")
                    };
                }
                _ => {}
            }
        }

        if let Some(s) = state {
            let _ = write!(cmd, " state {}", shell_escape(s));
        }

        cmd
    }

    /// Build a command to show network interfaces.
    ///
    /// Constructs: `ip -j addr show [{iface}]` (JSON output for parsing).
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `interface` is not a valid
    /// interface name.
    pub fn build_interfaces_command(interface: Option<&str>) -> Result<String> {
        let mut cmd = String::from("ip addr show");

        if let Some(iface) = interface {
            validate_interface(iface)?;
            let _ = write!(cmd, " dev {}", shell_escape(iface));
        }

        Ok(cmd)
    }

    /// Build a command to show the routing table.
    ///
    /// Constructs: `ip route show [{family}]`
    #[must_use]
    pub fn build_routes_command(family: Option<&str>) -> String {
        match family {
            Some("6" | "ipv6") => String::from("ip -6 route show"),
            _ => String::from("ip route show"),
        }
    }

    /// Build a `ping` command.
    ///
    /// Constructs: `ping -c {count} [-W {timeout}] [-I {interface}] {target}`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `target` is not a valid
    /// hostname or IP, or `interface` is not a valid interface name.
    pub fn build_ping_command(
        target: &str,
        count: Option<u32>,
        timeout: Option<u32>,
        interface: Option<&str>,
    ) -> Result<String> {
        validate_network_target(target)?;
        let c = count.unwrap_or(4);
        let mut cmd = format!("ping -c {c}");

        if let Some(t) = timeout {
            let _ = write!(cmd, " -W {t}");
        }

        if let Some(iface) = interface {
            validate_interface(iface)?;
            let _ = write!(cmd, " -I {}", shell_escape(iface));
        }

        let _ = write!(cmd, " {}", shell_escape(target));
        Ok(cmd)
    }

    /// Build a `traceroute` command.
    ///
    /// Constructs: `traceroute [-m {max_hops}] [-w {wait}] {target}`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `target` is not a valid hostname or IP.
    pub fn build_traceroute_command(
        target: &str,
        max_hops: Option<u32>,
        wait: Option<u32>,
    ) -> Result<String> {
        validate_network_target(target)?;
        let mut cmd = String::from("traceroute");

        if let Some(m) = max_hops {
            let _ = write!(cmd, " -m {m}");
        }

        if let Some(w) = wait {
            let _ = write!(cmd, " -w {w}");
        }

        let _ = write!(cmd, " {}", shell_escape(target));
        Ok(cmd)
    }

    /// Build a DNS lookup command.
    ///
    /// Constructs: `dig [{server}] {domain} [{record_type}] +short`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `domain` or `server` is not a
    /// valid hostname or IP, or `record_type` is not a valid DNS record type.
    pub fn build_dns_command(
        domain: &str,
        record_type: Option<&str>,
        server: Option<&str>,
        short: bool,
    ) -> Result<String> {
        validate_network_target(domain)?;
        let mut cmd = String::from("dig");

        if let Some(srv) = server {
            // `@{server}` is not an operand slot, but the server is still a
            // host: the same rule that governs `target` governs it.
            validate_network_target(srv)?;
            let _ = write!(cmd, " @{}", shell_escape(srv));
        }

        let _ = write!(cmd, " {}", shell_escape(domain));

        if let Some(rtype) = record_type {
            validate_record_type(rtype)?;
            let _ = write!(cmd, " {}", shell_escape(rtype));
        }

        if short {
            cmd.push_str(" +short");
        }

        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shell-escaping decides where a word ends, not how the program reads
    /// it. `dig '-f/etc/passwd'` is one shell word and still an option.
    #[test]
    fn a_target_cannot_become_an_option() {
        for hostile in ["-f/etc/passwd", "-h", "--help", "-"] {
            validate_network_target(hostile)
                .expect_err("a leading hyphen must be refused: {hostile}");
            NetworkCommandBuilder::build_ping_command(hostile, None, None, None)
                .expect_err("ping must refuse it too");
            NetworkCommandBuilder::build_traceroute_command(hostile, None, None)
                .expect_err("traceroute must refuse it too");
            NetworkCommandBuilder::build_dns_command(hostile, None, None, true)
                .expect_err("dig must refuse it too");
        }
    }

    /// These three had no validator at all — they were escaped and pasted.
    #[test]
    fn the_unvalidated_parameters_are_validated_now() {
        NetworkCommandBuilder::build_ping_command("example.com", None, None, Some("-f"))
            .expect_err("ping -I must not take an option as an interface");
        NetworkCommandBuilder::build_dns_command("example.com", None, Some("-f/etc/passwd"), true)
            .expect_err("dig @ must not take an option as a server");
        NetworkCommandBuilder::build_dns_command("example.com", Some("-f/etc/passwd"), None, true)
            .expect_err("dig must not take an option as a record type");
    }

    /// The ordinary shapes must still build, or the guard is just an outage.
    #[test]
    fn ordinary_diagnostics_still_build() {
        NetworkCommandBuilder::build_ping_command("192.168.1.1", Some(4), None, Some("eth0"))
            .expect("a plain ping");
        NetworkCommandBuilder::build_ping_command("example.com", None, None, Some("br-1a2b"))
            .expect("a bridge interface");
        NetworkCommandBuilder::build_dns_command(
            "example.com",
            Some("AAAA"),
            Some("1.1.1.1"),
            true,
        )
        .expect("a plain lookup");
        validate_interface("eth0.100").expect("a VLAN interface");
        validate_record_type("TYPE65").expect("an unnamed record type");
    }

    // ── build_connections_command ────────────────────────────────────

    #[test]
    fn test_connections_default() {
        let cmd = NetworkCommandBuilder::build_connections_command(None, None, false);
        assert_eq!(cmd, "ss -tunap");
    }

    #[test]
    fn test_connections_listening() {
        let cmd = NetworkCommandBuilder::build_connections_command(None, None, true);
        assert_eq!(cmd, "ss -tlnp");
    }

    #[test]
    fn test_connections_tcp_only() {
        let cmd = NetworkCommandBuilder::build_connections_command(Some("tcp"), None, false);
        assert_eq!(cmd, "ss -tnap");
    }

    #[test]
    fn test_connections_udp_listening() {
        let cmd = NetworkCommandBuilder::build_connections_command(Some("udp"), None, true);
        assert_eq!(cmd, "ss -ulnp");
    }

    #[test]
    fn test_connections_with_state() {
        let cmd =
            NetworkCommandBuilder::build_connections_command(None, Some("established"), false);
        assert!(cmd.contains("state 'established'"));
    }

    // ── build_interfaces_command ────────────────────────────────────

    #[test]
    fn test_interfaces_all() {
        let cmd = NetworkCommandBuilder::build_interfaces_command(None).unwrap();
        assert_eq!(cmd, "ip addr show");
    }

    #[test]
    fn test_interfaces_specific() {
        let cmd = NetworkCommandBuilder::build_interfaces_command(Some("eth0")).unwrap();
        assert_eq!(cmd, "ip addr show dev 'eth0'");
    }

    // ── build_routes_command ────────────────────────────────────────

    #[test]
    fn test_routes_default() {
        let cmd = NetworkCommandBuilder::build_routes_command(None);
        assert_eq!(cmd, "ip route show");
    }

    #[test]
    fn test_routes_ipv6() {
        let cmd = NetworkCommandBuilder::build_routes_command(Some("ipv6"));
        assert_eq!(cmd, "ip -6 route show");
    }

    #[test]
    fn test_routes_ipv6_short() {
        let cmd = NetworkCommandBuilder::build_routes_command(Some("6"));
        assert_eq!(cmd, "ip -6 route show");
    }

    // ── build_ping_command ──────────────────────────────────────────

    #[test]
    fn test_ping_default() {
        let cmd = NetworkCommandBuilder::build_ping_command("8.8.8.8", None, None, None).unwrap();
        assert_eq!(cmd, "ping -c 4 '8.8.8.8'");
    }

    #[test]
    fn test_ping_custom_count() {
        let cmd =
            NetworkCommandBuilder::build_ping_command("google.com", Some(10), None, None).unwrap();
        assert_eq!(cmd, "ping -c 10 'google.com'");
    }

    #[test]
    fn test_ping_with_timeout() {
        let cmd =
            NetworkCommandBuilder::build_ping_command("8.8.8.8", None, Some(5), None).unwrap();
        assert!(cmd.contains("-W 5"));
    }

    #[test]
    fn test_ping_with_interface() {
        let cmd =
            NetworkCommandBuilder::build_ping_command("8.8.8.8", None, None, Some("eth0")).unwrap();
        assert!(cmd.contains("-I 'eth0'"));
    }

    // ── build_traceroute_command ────────────────────────────────────

    #[test]
    fn test_traceroute_default() {
        let cmd =
            NetworkCommandBuilder::build_traceroute_command("google.com", None, None).unwrap();
        assert_eq!(cmd, "traceroute 'google.com'");
    }

    #[test]
    fn test_traceroute_with_max_hops() {
        let cmd =
            NetworkCommandBuilder::build_traceroute_command("google.com", Some(15), None).unwrap();
        assert!(cmd.contains("-m 15"));
    }

    #[test]
    fn test_traceroute_with_wait() {
        let cmd =
            NetworkCommandBuilder::build_traceroute_command("google.com", None, Some(3)).unwrap();
        assert!(cmd.contains("-w 3"));
    }

    // ── build_dns_command ───────────────────────────────────────────

    #[test]
    fn test_dns_simple() {
        let cmd =
            NetworkCommandBuilder::build_dns_command("example.com", None, None, false).unwrap();
        assert_eq!(cmd, "dig 'example.com'");
    }

    #[test]
    fn test_dns_with_type() {
        let cmd = NetworkCommandBuilder::build_dns_command("example.com", Some("MX"), None, false)
            .unwrap();
        assert!(cmd.contains("'MX'"));
    }

    #[test]
    fn test_dns_with_server() {
        let cmd =
            NetworkCommandBuilder::build_dns_command("example.com", None, Some("8.8.8.8"), false)
                .unwrap();
        assert!(cmd.contains("@'8.8.8.8'"));
    }

    #[test]
    fn test_dns_short() {
        let cmd =
            NetworkCommandBuilder::build_dns_command("example.com", None, None, true).unwrap();
        assert!(cmd.contains("+short"));
    }

    #[test]
    fn test_dns_all_options() {
        let cmd = NetworkCommandBuilder::build_dns_command(
            "example.com",
            Some("AAAA"),
            Some("1.1.1.1"),
            true,
        )
        .unwrap();
        assert!(cmd.contains("@'1.1.1.1'"));
        assert!(cmd.contains("'example.com'"));
        assert!(cmd.contains("'AAAA'"));
        assert!(cmd.contains("+short"));
    }

    // ── validate_network_target ────────────────────────────────────

    #[test]
    fn test_validate_target_valid() {
        assert!(validate_network_target("8.8.8.8").is_ok());
        assert!(validate_network_target("google.com").is_ok());
        assert!(validate_network_target("my-server.example.com").is_ok());
        assert!(validate_network_target("::1").is_ok());
        assert!(validate_network_target("2001:db8::1").is_ok());
        assert!(validate_network_target("10.0.0.0/8").is_ok());
    }

    #[test]
    fn test_validate_target_rejects_empty() {
        assert!(validate_network_target("").is_err());
    }

    #[test]
    fn test_validate_target_rejects_special_chars() {
        assert!(validate_network_target("host; rm -rf /").is_err());
        assert!(validate_network_target("host && whoami").is_err());
        assert!(validate_network_target("host | cat /etc/passwd").is_err());
        assert!(validate_network_target("$(whoami)").is_err());
    }
}
