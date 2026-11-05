//! Certificate Command Builder
//!
//! Builds TLS/SSL certificate inspection CLI commands for remote execution
//! via SSH. Uses `openssl` for certificate checking and inspection.

use std::fmt::Write;

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds certificate inspection commands for remote execution.
pub struct CertificateCommandBuilder;

impl CertificateCommandBuilder {
    /// Build a command to check a remote TLS certificate.
    ///
    /// Constructs: `echo | openssl s_client -connect {host}:{port} -servername {host}
    /// 2>/dev/null | openssl x509 -noout -text`
    #[must_use]
    pub fn build_check_command(host: &str, port: Option<u16>, servername: Option<&str>) -> String {
        let p = port.unwrap_or(443);
        let sni = servername.unwrap_or(host);
        format!(
            "echo | openssl s_client -connect {}:{p} -servername {} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint",
            shell_escape(host),
            shell_escape(sni)
        )
    }

    /// Build a command to inspect a local certificate file.
    ///
    /// Constructs: `openssl x509 -in {path} -noout -text`
    #[must_use]
    pub fn build_info_command(path: &str) -> String {
        format!("openssl x509 -in {} -noout -text", shell_escape(path))
    }

    /// Build a command to check certificate expiry.
    ///
    /// Constructs: `openssl x509 -in {path} -noout -enddate -checkend {days*86400}`
    /// or remote check via `s_client`.
    #[must_use]
    pub fn build_expiry_command(target: &str, is_file: bool, days_warning: Option<u32>) -> String {
        let check_secs = u64::from(days_warning.unwrap_or(30)) * 86_400;

        if is_file {
            format!(
                "openssl x509 -in {} -noout -enddate -checkend {check_secs}",
                shell_escape(target)
            )
        } else {
            let mut cmd = format!(
                "echo | openssl s_client -connect {} 2>/dev/null | openssl x509 -noout -enddate -checkend {check_secs}",
                shell_escape(target)
            );
            let _ = write!(cmd, "");
            cmd
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_default_port() {
        let cmd = CertificateCommandBuilder::build_check_command("example.com", None, None);
        assert!(cmd.contains("-connect 'example.com':443"));
        assert!(cmd.contains("-servername 'example.com'"));
    }

    #[test]
    fn test_check_custom_port() {
        let cmd = CertificateCommandBuilder::build_check_command("example.com", Some(8443), None);
        assert!(cmd.contains("-connect 'example.com':8443"));
    }

    #[test]
    fn test_check_custom_servername() {
        let cmd = CertificateCommandBuilder::build_check_command(
            "10.0.0.1",
            None,
            Some("myapp.example.com"),
        );
        assert!(cmd.contains("-connect '10.0.0.1':443"));
        assert!(cmd.contains("-servername 'myapp.example.com'"));
    }

    #[test]
    fn test_info_command() {
        let cmd = CertificateCommandBuilder::build_info_command("/etc/ssl/certs/server.crt");
        assert!(cmd.contains("-in '/etc/ssl/certs/server.crt'"));
        assert!(cmd.contains("-noout -text"));
    }

    #[test]
    fn test_expiry_file() {
        let cmd = CertificateCommandBuilder::build_expiry_command(
            "/etc/ssl/certs/server.crt",
            true,
            None,
        );
        assert!(cmd.contains("-in '/etc/ssl/certs/server.crt'"));
        assert!(cmd.contains("-checkend 2592000")); // 30 * 86400
    }

    #[test]
    fn test_expiry_remote() {
        let cmd =
            CertificateCommandBuilder::build_expiry_command("example.com:443", false, Some(7));
        assert!(cmd.contains("s_client -connect 'example.com:443'"));
        assert!(cmd.contains("-checkend 604800")); // 7 * 86400
    }

    #[test]
    fn test_expiry_huge_days_do_not_overflow() {
        let cmd = CertificateCommandBuilder::build_expiry_command("a.crt", true, Some(u32::MAX));
        assert!(cmd.contains("-checkend 371085174288000"), "{cmd}");
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_check_injection_in_host() {
        let cmd =
            CertificateCommandBuilder::build_check_command("example.com; rm -rf /", None, None);
        assert!(cmd.contains("-connect 'example.com; rm -rf /':443"));
        assert!(!cmd.contains("-connect example.com; rm"));
    }

    #[test]
    fn test_check_injection_in_servername() {
        let cmd = CertificateCommandBuilder::build_check_command(
            "10.0.0.1",
            None,
            Some("$(whoami).example.com"),
        );
        assert!(cmd.contains("-servername '$(whoami).example.com'"));
    }

    #[test]
    fn test_info_injection_in_path() {
        let cmd = CertificateCommandBuilder::build_info_command(
            "/etc/ssl/certs/server.crt; cat /etc/shadow",
        );
        assert!(cmd.contains("-in '/etc/ssl/certs/server.crt; cat /etc/shadow'"));
    }

    #[test]
    fn test_expiry_injection_in_target() {
        let cmd = CertificateCommandBuilder::build_expiry_command(
            "example.com:443 && whoami",
            false,
            None,
        );
        assert!(cmd.contains("-connect 'example.com:443 && whoami'"));
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_check_all_options() {
        let cmd = CertificateCommandBuilder::build_check_command(
            "10.0.0.1",
            Some(8443),
            Some("myapp.example.com"),
        );
        assert!(cmd.contains("-connect '10.0.0.1':8443"));
        assert!(cmd.contains("-servername 'myapp.example.com'"));
        assert!(cmd.starts_with("echo | openssl s_client"));
        assert!(cmd.contains("openssl x509 -noout -subject -issuer -dates -fingerprint"));
    }

    #[test]
    fn test_expiry_file_with_custom_days() {
        let cmd =
            CertificateCommandBuilder::build_expiry_command("/etc/ssl/cert.pem", true, Some(90));
        assert!(cmd.contains("-in '/etc/ssl/cert.pem'"));
        assert!(cmd.contains("-checkend 7776000")); // 90 * 86400
    }

    #[test]
    fn test_expiry_remote_with_default_days() {
        let cmd = CertificateCommandBuilder::build_expiry_command("example.com:443", false, None);
        assert!(cmd.contains("s_client -connect 'example.com:443'"));
        assert!(cmd.contains("-checkend 2592000")); // 30 * 86400
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_check_host_with_single_quotes() {
        let cmd = CertificateCommandBuilder::build_check_command("it's.example.com", None, None);
        assert!(cmd.contains("'it'\\''s.example.com'"));
    }

    #[test]
    fn test_info_path_with_spaces() {
        let cmd = CertificateCommandBuilder::build_info_command("/etc/ssl certs/my server.crt");
        assert!(cmd.contains("-in '/etc/ssl certs/my server.crt'"));
    }

    #[test]
    fn test_info_path_with_single_quotes() {
        let cmd = CertificateCommandBuilder::build_info_command("/etc/ssl/it's-cert.pem");
        assert!(cmd.contains("/etc/ssl/it'\\''s-cert.pem"));
    }

    #[test]
    fn test_expiry_days_warning_zero() {
        let cmd =
            CertificateCommandBuilder::build_expiry_command("/etc/ssl/cert.pem", true, Some(0));
        assert!(cmd.contains("-checkend 0"));
    }

    #[test]
    fn test_expiry_days_warning_large() {
        let cmd =
            CertificateCommandBuilder::build_expiry_command("/etc/ssl/cert.pem", true, Some(365));
        assert!(cmd.contains("-checkend 31536000")); // 365 * 86400
    }

    #[test]
    fn test_check_port_boundary_low() {
        let cmd = CertificateCommandBuilder::build_check_command("example.com", Some(1), None);
        assert!(cmd.contains(":1"));
    }

    #[test]
    fn test_check_port_boundary_high() {
        let cmd = CertificateCommandBuilder::build_check_command("example.com", Some(65535), None);
        assert!(cmd.contains(":65535"));
    }

    #[test]
    fn test_check_ipv6_host() {
        let cmd = CertificateCommandBuilder::build_check_command("::1", None, None);
        assert!(cmd.contains("-connect '::1':443"));
    }

    // ============== Minimal Command Tests ==============

    #[test]
    fn test_check_minimal() {
        let cmd = CertificateCommandBuilder::build_check_command("example.com", None, None);
        assert!(cmd.starts_with("echo | openssl s_client"));
        assert!(cmd.ends_with("-noout -subject -issuer -dates -fingerprint"));
        // servername defaults to host
        assert!(cmd.contains("-servername 'example.com'"));
    }

    #[test]
    fn test_info_minimal() {
        let cmd = CertificateCommandBuilder::build_info_command("/tmp/cert.pem");
        assert_eq!(cmd, "openssl x509 -in '/tmp/cert.pem' -noout -text");
    }

    #[test]
    fn test_expiry_file_minimal() {
        let cmd = CertificateCommandBuilder::build_expiry_command("/tmp/cert.pem", true, None);
        assert!(cmd.starts_with("openssl x509 -in '/tmp/cert.pem'"));
        assert!(cmd.contains("-checkend 2592000"));
        assert!(!cmd.contains("s_client"));
    }

    #[test]
    fn test_expiry_remote_minimal() {
        let cmd = CertificateCommandBuilder::build_expiry_command("example.com:443", false, None);
        assert!(cmd.contains("s_client"));
        assert!(cmd.contains("-checkend 2592000"));
    }
}
