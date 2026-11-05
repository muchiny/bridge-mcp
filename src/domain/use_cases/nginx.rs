//! Nginx Command Builder
//!
//! Builds Nginx web server management CLI commands for remote execution
//! via SSH. Auto-detects nginx or apache2/httpd.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Web servers whose binary `ssh_nginx_test` and `ssh_nginx_reload` may run.
const KNOWN_SERVERS: &[&str] = &["nginx", "apache2", "httpd", "openresty"];

/// Refuse a `server` that is not a known web server.
///
/// The test and reload commands run `<server> -t`, so the name is a program:
/// any other value (`bash`, `/tmp/payload.sh`) would run that program.
///
/// # Errors
///
/// Returns `BridgeError::CommandDenied` if `server` is not `nginx`, `apache2`,
/// `httpd` or `openresty`.
pub fn validate_server(server: Option<&str>) -> Result<()> {
    match server {
        Some(s) if !KNOWN_SERVERS.contains(&s) => Err(BridgeError::CommandDenied {
            reason: format!(
                "Unknown web server '{s}': 'server' must be one of {}",
                KNOWN_SERVERS.join(", ")
            ),
        }),
        _ => Ok(()),
    }
}

/// Builds Nginx/web server management commands for remote execution.
pub struct NginxCommandBuilder;

impl NginxCommandBuilder {
    /// Build a command to check web server status.
    ///
    /// Constructs: `systemctl status nginx` or `systemctl status apache2`
    #[must_use]
    pub fn build_status_command(server: Option<&str>) -> String {
        match server {
            Some(s) => format!("systemctl status --no-pager -- {}", shell_escape(s)),
            None => String::from(
                "if systemctl is-active nginx >/dev/null 2>&1; then systemctl status nginx --no-pager; \
                 elif systemctl is-active apache2 >/dev/null 2>&1; then systemctl status apache2 --no-pager; \
                 elif systemctl is-active httpd >/dev/null 2>&1; then systemctl status httpd --no-pager; \
                 else echo 'No web server running'; fi",
            ),
        }
    }

    /// Build a command to test web server configuration.
    ///
    /// Constructs: `nginx -t` or `apachectl configtest`
    #[must_use]
    pub fn build_test_command(server: Option<&str>) -> String {
        match server {
            Some("nginx") | None => String::from("nginx -t 2>&1"),
            Some("apache2" | "httpd") => String::from("apachectl configtest 2>&1"),
            Some(s) => format!("{} -t 2>&1", shell_escape(s)),
        }
    }

    /// Build a command to reload web server configuration.
    ///
    /// Constructs: `nginx -t && systemctl reload nginx`
    #[must_use]
    pub fn build_reload_command(server: Option<&str>) -> String {
        let srv = server.unwrap_or("nginx");
        match srv {
            "nginx" => String::from("nginx -t 2>&1 && systemctl reload nginx"),
            "apache2" | "httpd" => format!("apachectl configtest 2>&1 && systemctl reload {srv}"),
            _ => format!(
                "{} -t 2>&1 && systemctl reload -- {}",
                shell_escape(srv),
                shell_escape(srv)
            ),
        }
    }

    /// Build a command to list enabled sites.
    ///
    /// Constructs: `ls -la /etc/nginx/sites-enabled/` or `/etc/nginx/conf.d/`
    #[must_use]
    pub fn build_list_sites_command(server: Option<&str>, config_dir: Option<&str>) -> String {
        let dir = config_dir.unwrap_or(match server {
            Some("apache2") => "/etc/apache2/sites-enabled/",
            Some("httpd") => "/etc/httpd/conf.d/",
            _ => "/etc/nginx/sites-enabled/",
        });
        let mut cmd = format!("ls -la -- {} 2>/dev/null", shell_escape(dir));
        let _ = write!(
            cmd,
            " || ls -la /etc/nginx/conf.d/ 2>/dev/null || echo 'No sites directory found'"
        );
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_nginx() {
        let cmd = NginxCommandBuilder::build_status_command(Some("nginx"));
        assert!(cmd.contains("systemctl status --no-pager -- 'nginx'"));
    }

    #[test]
    fn test_status_auto() {
        let cmd = NginxCommandBuilder::build_status_command(None);
        assert!(cmd.contains("nginx"));
        assert!(cmd.contains("apache2"));
        assert!(cmd.contains("httpd"));
    }

    #[test]
    fn test_test_nginx() {
        let cmd = NginxCommandBuilder::build_test_command(Some("nginx"));
        assert_eq!(cmd, "nginx -t 2>&1");
    }

    #[test]
    fn test_test_default() {
        let cmd = NginxCommandBuilder::build_test_command(None);
        assert_eq!(cmd, "nginx -t 2>&1");
    }

    #[test]
    fn test_test_apache() {
        let cmd = NginxCommandBuilder::build_test_command(Some("apache2"));
        assert_eq!(cmd, "apachectl configtest 2>&1");
    }

    #[test]
    fn test_reload_nginx() {
        let cmd = NginxCommandBuilder::build_reload_command(Some("nginx"));
        assert!(cmd.contains("nginx -t"));
        assert!(cmd.contains("systemctl reload nginx"));
    }

    #[test]
    fn test_reload_apache() {
        let cmd = NginxCommandBuilder::build_reload_command(Some("apache2"));
        assert!(cmd.contains("apachectl configtest"));
        assert!(cmd.contains("systemctl reload apache2"));
    }

    #[test]
    fn test_list_sites_default() {
        let cmd = NginxCommandBuilder::build_list_sites_command(None, None);
        assert!(cmd.contains("/etc/nginx/sites-enabled/"));
    }

    #[test]
    fn test_list_sites_apache() {
        let cmd = NginxCommandBuilder::build_list_sites_command(Some("apache2"), None);
        assert!(cmd.contains("/etc/apache2/sites-enabled/"));
    }

    #[test]
    fn test_list_sites_custom_dir() {
        let cmd = NginxCommandBuilder::build_list_sites_command(None, Some("/opt/nginx/sites/"));
        assert!(cmd.contains("/opt/nginx/sites/"));
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_status_injection_in_server() {
        let cmd = NginxCommandBuilder::build_status_command(Some("nginx; rm -rf /"));
        assert!(cmd.contains("systemctl status --no-pager -- 'nginx; rm -rf /'"));
    }

    #[test]
    fn test_list_sites_injection_in_config_dir() {
        let cmd = NginxCommandBuilder::build_list_sites_command(
            None,
            Some("/etc/nginx/; cat /etc/shadow"),
        );
        assert!(cmd.contains("'/etc/nginx/; cat /etc/shadow'"));
    }

    #[test]
    fn test_reload_injection_custom_server() {
        let cmd = NginxCommandBuilder::build_reload_command(Some("nginx$(whoami)"));
        assert!(cmd.contains("'nginx$(whoami)'"));
        assert!(cmd.contains("-t 2>&1 && systemctl reload"));
    }

    // ============== Server Variant Tests ==============

    #[test]
    fn test_test_httpd() {
        let cmd = NginxCommandBuilder::build_test_command(Some("httpd"));
        assert_eq!(cmd, "apachectl configtest 2>&1");
    }

    #[test]
    fn test_test_custom_server() {
        let cmd = NginxCommandBuilder::build_test_command(Some("openresty"));
        assert_eq!(cmd, "'openresty' -t 2>&1");
    }

    #[test]
    fn test_reload_default() {
        let cmd = NginxCommandBuilder::build_reload_command(None);
        assert_eq!(cmd, "nginx -t 2>&1 && systemctl reload nginx");
    }

    #[test]
    fn test_reload_httpd() {
        let cmd = NginxCommandBuilder::build_reload_command(Some("httpd"));
        assert!(cmd.contains("apachectl configtest 2>&1"));
        assert!(cmd.contains("systemctl reload httpd"));
    }

    #[test]
    fn test_reload_custom_server_escaping() {
        let cmd = NginxCommandBuilder::build_reload_command(Some("openresty"));
        assert!(cmd.contains("'openresty' -t 2>&1"));
        assert!(cmd.contains("systemctl reload -- 'openresty'"));
    }

    #[test]
    fn test_status_apache2() {
        let cmd = NginxCommandBuilder::build_status_command(Some("apache2"));
        assert!(cmd.contains("systemctl status --no-pager -- 'apache2'"));
    }

    #[test]
    fn test_status_httpd() {
        let cmd = NginxCommandBuilder::build_status_command(Some("httpd"));
        assert!(cmd.contains("systemctl status --no-pager -- 'httpd'"));
    }

    #[test]
    fn test_list_sites_httpd() {
        let cmd = NginxCommandBuilder::build_list_sites_command(Some("httpd"), None);
        assert!(cmd.contains("/etc/httpd/conf.d/"));
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_list_sites_custom_dir_overrides_server_default() {
        let cmd = NginxCommandBuilder::build_list_sites_command(
            Some("apache2"),
            Some("/opt/custom/sites/"),
        );
        assert!(cmd.contains("'/opt/custom/sites/'"));
    }

    #[test]
    fn test_list_sites_custom_dir_with_spaces() {
        let cmd = NginxCommandBuilder::build_list_sites_command(None, Some("/opt/my sites/"));
        assert!(cmd.contains("'/opt/my sites/'"));
    }

    #[test]
    fn test_list_sites_fallback_to_conf_d() {
        let cmd = NginxCommandBuilder::build_list_sites_command(None, None);
        assert!(cmd.contains("/etc/nginx/conf.d/"));
        assert!(cmd.contains("echo 'No sites directory found'"));
    }

    #[test]
    fn test_status_auto_detect_all_servers() {
        let cmd = NginxCommandBuilder::build_status_command(None);
        assert!(cmd.contains("systemctl is-active nginx"));
        assert!(cmd.contains("systemctl is-active apache2"));
        assert!(cmd.contains("systemctl is-active httpd"));
        assert!(cmd.contains("No web server running"));
    }

    #[test]
    fn test_test_nginx_exact_output() {
        let cmd = NginxCommandBuilder::build_test_command(Some("nginx"));
        assert_eq!(cmd, "nginx -t 2>&1");
    }

    #[test]
    fn test_reload_nginx_exact_output() {
        let cmd = NginxCommandBuilder::build_reload_command(Some("nginx"));
        assert_eq!(cmd, "nginx -t 2>&1 && systemctl reload nginx");
    }

    #[test]
    fn test_list_sites_custom_dir_with_single_quotes() {
        let cmd =
            NginxCommandBuilder::build_list_sites_command(None, Some("/opt/it's-nginx/sites/"));
        assert!(cmd.contains("/opt/it'\\''s-nginx/sites/"));
    }

    #[test]
    fn test_status_and_reload_put_the_unit_after_double_dash() {
        let status = NginxCommandBuilder::build_status_command(Some("-.mount"));
        assert!(status.ends_with(" -- '-.mount'"), "{status}");
        let reload = NginxCommandBuilder::build_reload_command(Some("openresty"));
        assert!(
            reload.ends_with("systemctl reload -- 'openresty'"),
            "{reload}"
        );
    }

    #[test]
    fn test_list_sites_dir_goes_after_double_dash() {
        let cmd = NginxCommandBuilder::build_list_sites_command(None, Some("-R"));
        assert!(cmd.starts_with("ls -la -- '-R' 2>/dev/null"), "{cmd}");
    }

    #[test]
    fn test_validate_server_refuses_programs_and_options() {
        for bad in ["bash", "/tmp/payload.sh", "python3", "-v", ""] {
            let err = validate_server(Some(bad)).unwrap_err();
            assert!(err.to_string().contains("'server'"), "{err}");
        }
        for good in [
            None,
            Some("nginx"),
            Some("apache2"),
            Some("httpd"),
            Some("openresty"),
        ] {
            assert!(validate_server(good).is_ok(), "{good:?}");
        }
    }
}
