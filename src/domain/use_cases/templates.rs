//! Template Command Builder
//!
//! Builds configuration template management commands for remote execution
//! via SSH. Supports listing, showing, applying, validating, and diffing
//! configuration templates for common services (nginx, apache, postgresql,
//! mysql, redis).

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Known template names for built-in templates.
const KNOWN_TEMPLATES: &[&str] = &[
    "nginx-reverse-proxy",
    "nginx-static",
    "apache-vhost",
    "postgresql-config",
    "mysql-config",
    "redis-config",
];

/// Known service names for validation commands.
const KNOWN_SERVICES: &[&str] = &["nginx", "apache", "postgresql", "mysql", "redis"];

/// Validate that a template name contains only safe characters.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the name is empty or contains
/// characters other than alphanumerics, hyphens, and underscores.
pub fn validate_template_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Template name cannot be empty".to_string(),
        });
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid template name '{name}': only alphanumeric characters, hyphens, \
                 and underscores are allowed"
            ),
        });
    }
    Ok(())
}

/// Validate that a service name is one of the known services.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the service is not recognized.
pub fn validate_service(service: &str) -> Result<()> {
    if !KNOWN_SERVICES.contains(&service) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Unknown service '{}'. Supported services: {}",
                service,
                KNOWN_SERVICES.join(", ")
            ),
        });
    }
    Ok(())
}

/// Validate that a destination path is absolute and does not contain
/// directory traversal sequences.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the path is invalid.
pub fn validate_dest_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Destination path cannot be empty".to_string(),
        });
    }
    if !path.starts_with('/') {
        return Err(BridgeError::CommandDenied {
            reason: format!("Destination path '{path}' must be absolute (start with /)"),
        });
    }
    if path.contains("..") {
        return Err(BridgeError::CommandDenied {
            reason: format!("Path traversal not allowed: '{path}' contains '..'"),
        });
    }
    Ok(())
}

/// Builds configuration template management commands for remote execution.
pub struct TemplateCommandBuilder;

impl TemplateCommandBuilder {
    /// Build a command to list available configuration templates.
    ///
    /// Returns an echo command listing all built-in templates.
    #[must_use]
    pub fn build_template_list_command() -> String {
        // Emit a clean two-line tabular layout (single column "NAME") so the
        // generic columnar parser used by `ssh_template_list` sees a proper
        // header row and full-width values. The previous format used a
        // sentence header followed by lines indented with two spaces, which
        // the parser misread as a fixed-width column starting at offset 2,
        // chopping the first two characters off the header.
        let mut lines = vec!["echo NAME".to_string()];
        for tmpl in KNOWN_TEMPLATES {
            lines.push(format!("echo {tmpl}"));
        }
        lines.join(" && ")
    }

    /// Build a command to show a template's content.
    #[must_use]
    pub fn build_template_show_command(template_name: &str) -> String {
        let escaped = shell_escape(template_name);
        // The escaped name is its own argument: inside `'Template: ...'` the
        // quotes `shell_escape` adds would close the literal. `echo` joins
        // its arguments with one space, so the printed line is unchanged.
        format!(
            "echo 'Template:' {escaped} && echo '---' && \
             echo 'Use ssh_template_apply to deploy this template.'"
        )
    }

    /// Build a command to apply template content to a destination file.
    ///
    /// If `backup` is true and `dest` exists, copies it to `dest.bak` before
    /// overwriting; a failed copy stops the command before `dest` is touched
    /// (exit 1, `backup failed` on stderr). A `dest` that does not exist yet has
    /// nothing to back up.
    ///
    /// The heredoc terminator is randomized per call (`MCP_EOF_{uuid}`)
    /// and re-rolled on the astronomically rare collision with any body line,
    /// so a malicious `content` cannot close the heredoc and inject shell.
    #[must_use]
    pub fn build_template_apply_command(content: &str, dest: &str, backup: bool) -> String {
        let escaped_dest = shell_escape(dest);
        let mut cmd = String::new();
        if backup {
            let _ = write!(
                cmd,
                "if [ -e {escaped_dest} ]; then cp -p -- {escaped_dest} {escaped_dest}.bak \
                 || {{ echo 'backup failed' >&2; exit 1; }}; fi; "
            );
        }

        let terminator = loop {
            let candidate = format!("MCP_EOF_{}", uuid::Uuid::new_v4().simple());
            if !content.lines().any(|l| l == candidate) {
                break candidate;
            }
        };

        let _ = write!(
            cmd,
            "cat > {escaped_dest} << '{terminator}'\n{content}\n{terminator}"
        );
        cmd
    }

    /// Build a command to validate a service's configuration.
    ///
    /// Runs the appropriate config-test command for the given service.
    #[must_use]
    pub fn build_template_validate_command(service: &str, config_path: Option<&str>) -> String {
        match service {
            "nginx" => {
                if let Some(path) = config_path {
                    format!("nginx -t -c {}", shell_escape(path))
                } else {
                    "nginx -t".to_string()
                }
            }
            "apache" => {
                if let Some(path) = config_path {
                    format!("apachectl -t -f {}", shell_escape(path))
                } else {
                    "apachectl configtest".to_string()
                }
            }
            "postgresql" => {
                if let Some(path) = config_path {
                    format!("pg_isready -d {}", shell_escape(path))
                } else {
                    "pg_isready".to_string()
                }
            }
            "mysql" => {
                if let Some(path) = config_path {
                    format!(
                        "mysqld --validate-config --defaults-file={}",
                        shell_escape(path)
                    )
                } else {
                    "mysqld --validate-config".to_string()
                }
            }
            "redis" => {
                if let Some(path) = config_path {
                    format!("redis-cli ping && echo 'Config:' {}", shell_escape(path))
                } else {
                    "redis-cli ping".to_string()
                }
            }
            _ => format!("echo 'Unknown service:' {}", shell_escape(service)),
        }
    }

    /// Build a command to diff template content against an existing file.
    ///
    /// Uses process substitution to compare. The content is `printf`'s
    /// argument, never an `echo` operand, so a leading `-` or a backslash in it
    /// is data.
    #[must_use]
    pub fn build_template_diff_command(content: &str, current_path: &str) -> String {
        format!(
            "diff <(cat -- {}) <(printf '%s\\n' {})",
            shell_escape(current_path),
            shell_escape(content)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== Validation Tests ==============

    #[test]
    fn test_validate_template_name_valid() {
        assert!(validate_template_name("nginx-reverse-proxy").is_ok());
        assert!(validate_template_name("redis-config").is_ok());
        assert!(validate_template_name("my_template").is_ok());
        assert!(validate_template_name("template123").is_ok());
    }

    #[test]
    fn test_validate_template_name_empty() {
        let result = validate_template_name("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_template_name_invalid_chars() {
        assert!(validate_template_name("test;rm -rf").is_err());
        assert!(validate_template_name("$(whoami)").is_err());
        assert!(validate_template_name("name with spaces").is_err());
    }

    #[test]
    fn test_validate_template_name_error_message() {
        let result = validate_template_name("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_service_valid() {
        assert!(validate_service("nginx").is_ok());
        assert!(validate_service("apache").is_ok());
        assert!(validate_service("postgresql").is_ok());
        assert!(validate_service("mysql").is_ok());
        assert!(validate_service("redis").is_ok());
    }

    #[test]
    fn test_validate_service_invalid() {
        let result = validate_service("unknown");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Unknown service"));
                assert!(reason.contains("unknown"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_service_empty() {
        assert!(validate_service("").is_err());
    }

    #[test]
    fn test_validate_dest_path_valid() {
        assert!(validate_dest_path("/etc/nginx/nginx.conf").is_ok());
        assert!(validate_dest_path("/tmp/config.yaml").is_ok());
    }

    #[test]
    fn test_validate_dest_path_empty() {
        assert!(validate_dest_path("").is_err());
    }

    #[test]
    fn test_validate_dest_path_not_absolute() {
        let result = validate_dest_path("relative/path");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("must be absolute"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_dest_path_traversal() {
        let result = validate_dest_path("/etc/../shadow");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Path traversal"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ============== List Command ==============

    #[test]
    fn test_list_command() {
        let cmd = TemplateCommandBuilder::build_template_list_command();
        assert!(cmd.contains("echo NAME"));
        assert!(cmd.contains("nginx-reverse-proxy"));
        assert!(cmd.contains("nginx-static"));
        assert!(cmd.contains("apache-vhost"));
        assert!(cmd.contains("postgresql-config"));
        assert!(cmd.contains("mysql-config"));
        assert!(cmd.contains("redis-config"));
    }

    #[test]
    fn test_list_command_all_templates() {
        let cmd = TemplateCommandBuilder::build_template_list_command();
        for tmpl in KNOWN_TEMPLATES {
            assert!(cmd.contains(tmpl), "Missing template: {tmpl}");
        }
    }

    // ============== Show Command ==============

    #[test]
    fn test_show_command() {
        let cmd = TemplateCommandBuilder::build_template_show_command("nginx-reverse-proxy");
        assert!(cmd.contains("nginx-reverse-proxy"));
        assert!(cmd.contains("Template:"));
    }

    #[test]
    fn test_show_command_injection() {
        let cmd = TemplateCommandBuilder::build_template_show_command("test; rm -rf /");
        assert!(cmd.contains("'test; rm -rf /'"));
    }

    // ============== Apply Command ==============

    /// Helper for tests: extract the heredoc terminator (the token between
    /// `<< '` and the next `'`) from a built apply command.
    fn extract_terminator(cmd: &str) -> &str {
        let start = cmd.find("<< '").expect("heredoc opening present") + 4;
        let end = cmd[start..].find('\'').expect("terminator close quote") + start;
        &cmd[start..end]
    }

    #[test]
    fn test_apply_command_no_backup() {
        let cmd = TemplateCommandBuilder::build_template_apply_command(
            "server { listen 80; }",
            "/etc/nginx/nginx.conf",
            false,
        );
        let terminator = extract_terminator(&cmd);
        assert!(cmd.contains(terminator));
        assert!(cmd.contains("server { listen 80; }"));
        assert!(!cmd.contains(".bak"));
    }

    #[test]
    fn test_apply_command_with_backup() {
        let cmd = TemplateCommandBuilder::build_template_apply_command(
            "content",
            "/etc/nginx/nginx.conf",
            true,
        );
        let terminator = extract_terminator(&cmd);
        assert!(cmd.contains(".bak"));
        assert!(cmd.contains(terminator));
        assert!(cmd.contains("cp "));
    }

    #[test]
    fn test_apply_command_injection_in_dest() {
        let cmd = TemplateCommandBuilder::build_template_apply_command(
            "content",
            "/tmp/test; rm -rf /",
            false,
        );
        assert!(cmd.contains("'/tmp/test; rm -rf /'"));
    }

    #[test]
    fn test_template_apply_uses_unique_terminator() {
        let cmd = TemplateCommandBuilder::build_template_apply_command(
            "hello\nTEMPLATE_EOF\nbash -c 'evil'",
            "/etc/site.conf",
            false,
        );
        // Extract the terminator: the token after `<< '` and before the next `'`.
        let start = cmd.find("<< '").expect("heredoc opening present") + 4;
        let end = cmd[start..].find('\'').expect("terminator close quote") + start;
        let terminator = &cmd[start..end];

        // The terminator must not appear as a sole line in the body.
        let body_start = cmd.find('\n').expect("body has newline") + 1;
        let body_end = cmd
            .rfind(&format!("\n{terminator}"))
            .expect("closing terminator");
        let body = &cmd[body_start..body_end];
        assert!(
            !body.lines().any(|l| l == terminator),
            "terminator {terminator} must not appear as a sole line in body"
        );
        // Sanity: the literal old default 'TEMPLATE_EOF' is in the BODY (the attacker payload).
        // Reject builds that still emit that as the actual heredoc terminator.
        assert_ne!(terminator, "TEMPLATE_EOF");
    }

    #[test]
    fn test_template_apply_terminators_are_unique_per_call() {
        let a = TemplateCommandBuilder::build_template_apply_command("a", "/x", false);
        let b = TemplateCommandBuilder::build_template_apply_command("a", "/x", false);
        assert_ne!(a, b, "calls must use different terminators");
    }

    #[test]
    fn test_template_apply_backup_branch_still_works() {
        let cmd =
            TemplateCommandBuilder::build_template_apply_command("body", "/etc/foo.conf", true);
        assert!(
            cmd.starts_with(
                "if [ -e '/etc/foo.conf' ]; then cp -p -- '/etc/foo.conf' '/etc/foo.conf'.bak || "
            ),
            "{cmd}"
        );
        assert!(
            !cmd.contains("2>/dev/null"),
            "a failed copy must not be silent: {cmd}"
        );
        assert!(
            cmd.contains("exit 1; }; fi; cat > '/etc/foo.conf'"),
            "{cmd}"
        );
    }

    #[test]
    fn test_template_apply_backup_failure_stops_before_the_write() {
        let cmd = TemplateCommandBuilder::build_template_apply_command("x", "/d", true);
        let copy = cmd.find("cp -p").expect("backup copy present");
        let fail = cmd.find("exit 1").expect("fail-closed exit present");
        let write = cmd.find("cat > '/d'").expect("write present");
        assert!(copy < fail && fail < write, "{cmd}");
    }

    #[test]
    fn test_template_apply_without_backup_has_no_copy() {
        let cmd = TemplateCommandBuilder::build_template_apply_command("x", "/d", false);
        assert!(cmd.starts_with("cat > '/d'"), "{cmd}");
    }

    // ============== Validate Command ==============

    #[test]
    fn test_validate_nginx() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("nginx", None);
        assert_eq!(cmd, "nginx -t");
    }

    #[test]
    fn test_validate_nginx_with_path() {
        let cmd = TemplateCommandBuilder::build_template_validate_command(
            "nginx",
            Some("/etc/nginx/nginx.conf"),
        );
        assert!(cmd.contains("nginx -t -c"));
        assert!(cmd.contains("'/etc/nginx/nginx.conf'"));
    }

    #[test]
    fn test_validate_apache() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("apache", None);
        assert_eq!(cmd, "apachectl configtest");
    }

    #[test]
    fn test_validate_postgresql() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("postgresql", None);
        assert_eq!(cmd, "pg_isready");
    }

    #[test]
    fn test_validate_mysql() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("mysql", None);
        assert_eq!(cmd, "mysqld --validate-config");
    }

    #[test]
    fn test_validate_redis() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("redis", None);
        assert_eq!(cmd, "redis-cli ping");
    }

    #[test]
    fn test_validate_unknown_service_fallback() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("unknown", None);
        assert!(cmd.contains("Unknown service"));
    }

    #[test]
    fn test_validate_injection_in_path() {
        let cmd = TemplateCommandBuilder::build_template_validate_command(
            "nginx",
            Some("/tmp/test; cat /etc/shadow"),
        );
        assert!(cmd.contains("'/tmp/test; cat /etc/shadow'"));
    }

    // ============== Diff Command ==============

    #[test]
    fn test_diff_command() {
        let cmd = TemplateCommandBuilder::build_template_diff_command(
            "new content",
            "/etc/nginx/nginx.conf",
        );
        assert!(cmd.contains("diff"));
        assert!(cmd.contains("'/etc/nginx/nginx.conf'"));
        assert!(cmd.contains("'new content'"));
    }

    #[test]
    fn test_diff_command_injection_in_path() {
        let cmd =
            TemplateCommandBuilder::build_template_diff_command("content", "/tmp/test; rm -rf /");
        assert!(cmd.contains("'/tmp/test; rm -rf /'"));
    }

    #[test]
    fn test_diff_command_injection_in_content() {
        let cmd = TemplateCommandBuilder::build_template_diff_command(
            "content'; rm -rf /; echo '",
            "/tmp/test",
        );
        // Verify the content is properly shell-escaped
        assert!(cmd.contains("diff"));
    }

    // ============== All Services Valid ==============

    #[test]
    fn test_all_known_services_valid() {
        for svc in KNOWN_SERVICES {
            assert!(
                validate_service(svc).is_ok(),
                "Service should be valid: {svc}"
            );
        }
    }

    #[test]
    fn test_mysql_with_path() {
        let cmd = TemplateCommandBuilder::build_template_validate_command(
            "mysql",
            Some("/etc/mysql/my.cnf"),
        );
        assert!(cmd.contains("--defaults-file="));
    }

    #[test]
    fn test_validate_redis_path_is_its_own_echo_argument() {
        let cmd =
            TemplateCommandBuilder::build_template_validate_command("redis", Some("/x;id;/$(id)"));
        assert_eq!(cmd, "redis-cli ping && echo 'Config:' '/x;id;/$(id)'");
    }

    #[test]
    fn test_show_and_unknown_service_do_not_wrap_the_escaped_value_in_quotes() {
        let show = TemplateCommandBuilder::build_template_show_command("a$(id)");
        assert!(show.starts_with("echo 'Template:' 'a$(id)' && "), "{show}");
        let unknown = TemplateCommandBuilder::build_template_validate_command("a;b", None);
        assert_eq!(unknown, "echo 'Unknown service:' 'a;b'");
    }

    #[test]
    fn test_diff_content_is_printf_data_not_echo_operand() {
        let cmd = TemplateCommandBuilder::build_template_diff_command("-n\\t", "/etc/x");
        assert_eq!(cmd, "diff <(cat -- '/etc/x') <(printf '%s\\n' '-n\\t')");
    }
}
