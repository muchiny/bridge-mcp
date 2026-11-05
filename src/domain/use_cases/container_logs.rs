//! Container Log Analysis Command Builder
//!
//! Builds commands for searching, analyzing, and inspecting Docker/Podman
//! container logs on remote hosts. Supports auto-detection of the container
//! runtime binary (`docker` or `podman`).

use std::fmt::Write;

use crate::config::ShellType;
use crate::domain::use_cases::docker::docker_detect_prefix;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds container log analysis CLI commands for remote execution.
pub struct ContainerLogCommandBuilder;

impl ContainerLogCommandBuilder {
    /// Validate a container name or ID.
    ///
    /// Must be non-empty, must not start with `-` (the runtime would read it
    /// as an option) and contain only alphanumeric characters, hyphens,
    /// underscores, dots, slashes, and colons.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the name is invalid.
    pub fn validate_container_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Container name cannot be empty".to_string(),
            });
        }
        super::shell::refuse_option_like("container", name)?;
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'))
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Container name contains invalid characters: '{name}'. \
                     Only alphanumeric, '-', '_', '.', '/', ':' are allowed."
                ),
            });
        }
        Ok(())
    }

    /// Validate a search pattern.
    ///
    /// Must be non-empty, at most 500 characters, and must not contain
    /// shell metacharacters that could enable injection.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the pattern is invalid.
    pub fn validate_pattern(pattern: &str) -> Result<()> {
        if pattern.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Search pattern cannot be empty".to_string(),
            });
        }
        if pattern.len() > 500 {
            return Err(BridgeError::CommandDenied {
                reason: format!("Search pattern too long ({} chars, max 500)", pattern.len()),
            });
        }
        // Reject shell injection characters
        if pattern.contains('`')
            || pattern.contains("$(")
            || pattern.contains(';')
            || pattern.contains('|')
            || pattern.contains('&')
            || pattern.contains('\n')
        {
            return Err(BridgeError::CommandDenied {
                reason: "Search pattern contains disallowed shell characters".to_string(),
            });
        }
        Ok(())
    }

    /// Validate an event type filter.
    ///
    /// Must be one of `container`, `image`, `network`, or `volume`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the event type is not allowed.
    pub fn validate_event_type(event_type: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["container", "image", "network", "volume"];
        if ALLOWED.contains(&event_type) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid event type '{event_type}'. \
                     Allowed: container, image, network, volume"
                ),
            })
        }
    }

    /// Build a command to search container logs for a pattern.
    ///
    /// Constructs: `{docker} logs {container} [--since {since}] [--tail {tail}]
    /// 2>&1 | grep -i -- {pattern}`
    ///
    /// The `--` keeps a pattern that starts with `-` a pattern, not a `grep`
    /// option (`-rHe.` would otherwise search the working directory).
    #[must_use]
    pub fn build_log_search_command(
        docker_bin: Option<&str>,
        container: &str,
        pattern: &str,
        since: Option<&str>,
        tail: Option<u64>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let escaped_container = shell_escape(container);
        let mut cmd = format!("{prefix}logs {escaped_container}");

        if let Some(s) = since {
            let _ = write!(cmd, " --since {}", shell_escape(s));
        }

        if let Some(n) = tail {
            let _ = write!(cmd, " --tail={n}");
        }

        let escaped_pattern = shell_escape(pattern);
        let _ = write!(cmd, " 2>&1 | grep -i -- {escaped_pattern}");

        cmd
    }

    /// Build a command to show log statistics for a container.
    ///
    /// Counts total lines, error lines, warning lines, and shows
    /// the top unique error patterns.
    #[must_use]
    pub fn build_log_stats_command(
        docker_bin: Option<&str>,
        container: &str,
        since: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let escaped_container = shell_escape(container);
        let mut logs_cmd = format!("{prefix}logs {escaped_container}");

        if let Some(s) = since {
            let _ = write!(logs_cmd, " --since {}", shell_escape(s));
        }

        logs_cmd.push_str(" 2>&1");

        // Compound command that computes stats from the log output
        format!(
            "LOGS=$({logs_cmd}); \
             echo \"=== Log Statistics ===\"; \
             echo \"Total lines: $(echo \"$LOGS\" | wc -l)\"; \
             echo \"Error lines: $(echo \"$LOGS\" | grep -ic 'error' || true)\"; \
             echo \"Warning lines: $(echo \"$LOGS\" | grep -ic 'warn' || true)\"; \
             echo \"Fatal lines: $(echo \"$LOGS\" | grep -ic 'fatal' || true)\"; \
             echo \"=== Top Error Patterns ===\"; \
             echo \"$LOGS\" | grep -i 'error' | sort | uniq -c | sort -rn | head -10 || true"
        )
    }

    /// Build a command to show Docker daemon events.
    ///
    /// Constructs: `{docker} events --since {since} --until {until}
    /// [--filter type={event_type}] --format '{{json .}}'`
    #[must_use]
    pub fn build_events_command(
        docker_bin: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
        event_type: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let since_val = since.unwrap_or("1h");
        let until_val = until.unwrap_or("now");

        let mut cmd = format!(
            "{prefix}events --since {} --until {}",
            shell_escape(since_val),
            shell_escape(until_val),
        );

        if let Some(et) = event_type {
            let _ = write!(cmd, " --filter type={}", shell_escape(et));
        }

        cmd.push_str(" --format '{{json .}}'");

        cmd
    }

    /// Build a command to show health check history for a container.
    ///
    /// Constructs: `{docker} inspect --format '{{json .State.Health}}' {container}`
    #[must_use]
    pub fn build_health_history_command(docker_bin: Option<&str>, container: &str) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let escaped_container = shell_escape(container);
        format!("{prefix}inspect --format '{{{{json .State.Health}}}}' {escaped_container}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== validate_container_name tests ==============

    #[test]
    fn test_validate_container_name_valid() {
        assert!(ContainerLogCommandBuilder::validate_container_name("nginx").is_ok());
        assert!(ContainerLogCommandBuilder::validate_container_name("my-app").is_ok());
        assert!(ContainerLogCommandBuilder::validate_container_name("app_v2").is_ok());
        assert!(ContainerLogCommandBuilder::validate_container_name("registry.io/app:v1").is_ok());
        assert!(ContainerLogCommandBuilder::validate_container_name("abc123").is_ok());
    }

    #[test]
    fn test_validate_container_name_empty() {
        let result = ContainerLogCommandBuilder::validate_container_name("");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("empty"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_container_name_invalid_chars() {
        assert!(ContainerLogCommandBuilder::validate_container_name("ng;inx").is_err());
        assert!(ContainerLogCommandBuilder::validate_container_name("ng|inx").is_err());
        assert!(ContainerLogCommandBuilder::validate_container_name("ng`inx").is_err());
        assert!(ContainerLogCommandBuilder::validate_container_name("ng$inx").is_err());
        assert!(ContainerLogCommandBuilder::validate_container_name("ng inx").is_err());
    }

    #[test]
    fn test_validate_container_name_refuses_leading_dash() {
        let err = ContainerLogCommandBuilder::validate_container_name("-x").unwrap_err();
        assert!(
            err.to_string()
                .contains("'container' must not start with '-'")
        );
        assert!(ContainerLogCommandBuilder::validate_container_name("a-x").is_ok());
    }

    #[test]
    fn test_log_search_pattern_after_double_dash() {
        let cmd = ContainerLogCommandBuilder::build_log_search_command(
            Some("docker"),
            "app",
            "-rHe.",
            None,
            None,
        );
        assert!(cmd.ends_with(" 2>&1 | grep -i -- '-rHe.'"), "{cmd}");
    }

    // ============== validate_pattern tests ==============

    #[test]
    fn test_validate_pattern_valid() {
        assert!(ContainerLogCommandBuilder::validate_pattern("error").is_ok());
        assert!(ContainerLogCommandBuilder::validate_pattern("OOM killed").is_ok());
        assert!(ContainerLogCommandBuilder::validate_pattern("connection refused").is_ok());
    }

    #[test]
    fn test_validate_pattern_empty() {
        let result = ContainerLogCommandBuilder::validate_pattern("");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("empty"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_pattern_too_long() {
        let long_pattern = "a".repeat(501);
        let result = ContainerLogCommandBuilder::validate_pattern(&long_pattern);
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("too long"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_pattern_max_length_ok() {
        let pattern = "a".repeat(500);
        assert!(ContainerLogCommandBuilder::validate_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_validate_pattern_shell_injection() {
        assert!(ContainerLogCommandBuilder::validate_pattern("foo; rm -rf /").is_err());
        assert!(ContainerLogCommandBuilder::validate_pattern("foo | cat /etc/passwd").is_err());
        assert!(ContainerLogCommandBuilder::validate_pattern("foo & bg").is_err());
        assert!(ContainerLogCommandBuilder::validate_pattern("foo`id`").is_err());
        assert!(ContainerLogCommandBuilder::validate_pattern("$(whoami)").is_err());
        assert!(ContainerLogCommandBuilder::validate_pattern("foo\nbar").is_err());
    }

    // ============== validate_event_type tests ==============

    #[test]
    fn test_validate_event_type_valid() {
        assert!(ContainerLogCommandBuilder::validate_event_type("container").is_ok());
        assert!(ContainerLogCommandBuilder::validate_event_type("image").is_ok());
        assert!(ContainerLogCommandBuilder::validate_event_type("network").is_ok());
        assert!(ContainerLogCommandBuilder::validate_event_type("volume").is_ok());
    }

    #[test]
    fn test_validate_event_type_invalid() {
        let result = ContainerLogCommandBuilder::validate_event_type("daemon");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Invalid event type"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ============== build_log_search_command tests ==============

    #[test]
    fn test_build_log_search_basic() {
        let cmd = ContainerLogCommandBuilder::build_log_search_command(
            Some("docker"),
            "nginx",
            "error",
            None,
            None,
        );
        assert!(cmd.contains("docker logs"));
        assert!(cmd.contains("nginx"));
        assert!(cmd.contains("grep -i"));
        assert!(cmd.contains("error"));
    }

    #[test]
    fn test_build_log_search_with_since_and_tail() {
        let cmd = ContainerLogCommandBuilder::build_log_search_command(
            Some("docker"),
            "nginx",
            "timeout",
            Some("1h"),
            Some(200),
        );
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("1h"));
        assert!(cmd.contains("--tail=200"));
        assert!(cmd.contains("grep -i"));
    }

    #[test]
    fn test_build_log_search_auto_detect() {
        let cmd = ContainerLogCommandBuilder::build_log_search_command(
            None,
            "webapp",
            "exception",
            None,
            None,
        );
        assert!(cmd.contains("command -v docker"));
        assert!(cmd.contains("podman"));
        assert!(cmd.contains("grep -i"));
    }

    // ============== build_log_stats_command tests ==============

    #[test]
    fn test_build_log_stats_basic() {
        let cmd =
            ContainerLogCommandBuilder::build_log_stats_command(Some("docker"), "nginx", None);
        assert!(cmd.contains("docker logs"));
        assert!(cmd.contains("nginx"));
        assert!(cmd.contains("wc -l"));
        assert!(cmd.contains("grep -ic 'error'"));
        assert!(cmd.contains("grep -ic 'warn'"));
        assert!(cmd.contains("Log Statistics"));
    }

    #[test]
    fn test_build_log_stats_with_since() {
        let cmd = ContainerLogCommandBuilder::build_log_stats_command(
            Some("docker"),
            "webapp",
            Some("2h"),
        );
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("2h"));
    }

    // ============== build_events_command tests ==============

    #[test]
    fn test_build_events_defaults() {
        let cmd =
            ContainerLogCommandBuilder::build_events_command(Some("docker"), None, None, None);
        assert!(cmd.contains("docker events"));
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("1h"));
        assert!(cmd.contains("--until"));
        assert!(cmd.contains("now"));
        assert!(cmd.contains("json"));
    }

    #[test]
    fn test_build_events_with_type_filter() {
        let cmd = ContainerLogCommandBuilder::build_events_command(
            Some("docker"),
            Some("30m"),
            Some("10m"),
            Some("container"),
        );
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("30m"));
        assert!(cmd.contains("--until"));
        assert!(cmd.contains("10m"));
        assert!(cmd.contains("--filter type="));
        assert!(cmd.contains("container"));
    }

    #[test]
    fn test_build_events_auto_detect() {
        let cmd = ContainerLogCommandBuilder::build_events_command(None, None, None, None);
        assert!(cmd.contains("command -v docker"));
    }

    // ============== build_health_history_command tests ==============

    #[test]
    fn test_build_health_history_basic() {
        let cmd = ContainerLogCommandBuilder::build_health_history_command(Some("docker"), "nginx");
        assert!(cmd.contains("docker inspect"));
        assert!(cmd.contains("State.Health"));
        assert!(cmd.contains("nginx"));
    }

    #[test]
    fn test_build_health_history_podman() {
        let cmd =
            ContainerLogCommandBuilder::build_health_history_command(Some("podman"), "webapp");
        assert!(cmd.contains("podman inspect"));
        assert!(cmd.contains("webapp"));
    }

    #[test]
    fn test_build_health_history_auto_detect() {
        let cmd = ContainerLogCommandBuilder::build_health_history_command(None, "my-container");
        assert!(cmd.contains("command -v docker"));
        assert!(cmd.contains("my-container"));
    }
}
