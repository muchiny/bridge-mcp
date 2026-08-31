//! Docker Command Builder
//!
//! Builds Docker and Docker Compose CLI commands for remote execution via SSH.
//! Supports auto-detection of docker binary (`docker` or `podman`) and
//! compose binary (`docker compose` v2 or `docker-compose` v1).

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Known multi-word commands that are valid binary specifications.
const KNOWN_MULTI_WORD: &[&str] = &["docker compose"];

/// Validate a binary path contains only safe characters.
fn is_valid_binary_path(bin: &str) -> bool {
    if KNOWN_MULTI_WORD.contains(&bin) {
        return true;
    }
    !bin.is_empty()
        && bin
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

/// Generate the docker binary detection prefix.
///
/// If `docker_bin` is provided, use it directly. Otherwise, auto-detect
/// by probing for `docker` or `podman`.
#[must_use]
pub fn docker_detect_prefix(docker_bin: Option<&str>) -> String {
    let Some(bin) = docker_bin else {
        return "$(if command -v docker >/dev/null 2>&1; then echo docker; \
         elif command -v podman >/dev/null 2>&1; then echo podman; \
         else echo 'Docker/Podman not installed on host' >&2; echo false; fi) "
            .to_string();
    };
    if is_valid_binary_path(bin) {
        format!("{bin} ")
    } else {
        // Invalid binary path, fall back to auto-detection
        docker_detect_prefix(None)
    }
}

/// Generate the docker compose binary detection prefix.
///
/// If `compose_bin` is provided, use it directly. Otherwise, auto-detect
/// `docker compose` (v2 plugin) or `docker-compose` (v1 standalone).
#[must_use]
pub fn docker_compose_detect_prefix(compose_bin: Option<&str>) -> String {
    let Some(bin) = compose_bin else {
        return "$(if docker compose version >/dev/null 2>&1 2>&1; then echo 'docker compose'; \
         elif command -v docker-compose >/dev/null 2>&1; then echo docker-compose; \
         else echo 'docker compose / docker-compose not installed on host' >&2; echo false; fi) "
            .to_string();
    };
    if is_valid_binary_path(bin) {
        format!("{bin} ")
    } else {
        // Invalid binary path, fall back to auto-detection
        docker_compose_detect_prefix(None)
    }
}

/// Builds Docker CLI commands for remote execution.
pub struct DockerCommandBuilder;

impl DockerCommandBuilder {
    /// Build a `docker ps` command.
    ///
    /// Constructs: `{docker} ps [--all] [--filter {f}] [--format {fmt}]`
    #[must_use]
    pub fn build_ps_command(
        docker_bin: Option<&str>,
        all: bool,
        filter: Option<&str>,
        format: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let mut cmd = format!("{prefix}ps");

        if all {
            cmd.push_str(" --all");
        }

        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        cmd
    }

    /// Build a `docker logs` command.
    ///
    /// Constructs: `{docker} logs {container} [--tail={N}] [--since={s}]
    /// [--until={u}] [--timestamps]`
    ///
    /// Note: `--follow` is intentionally omitted to avoid blocking over SSH.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_logs_command(
        docker_bin: Option<&str>,
        container: &str,
        tail: Option<u64>,
        since: Option<&str>,
        until: Option<&str>,
        timestamps: bool,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let escaped_container = shell_escape(container);
        let mut cmd = format!("{prefix}logs {escaped_container}");

        if let Some(n) = tail {
            let _ = write!(cmd, " --tail={n}");
        }

        if let Some(s) = since {
            let _ = write!(cmd, " --since {}", shell_escape(s));
        }

        if let Some(u) = until {
            let _ = write!(cmd, " --until {}", shell_escape(u));
        }

        if timestamps {
            cmd.push_str(" --timestamps");
        }

        cmd
    }

    /// Build a `docker inspect` command.
    ///
    /// Constructs: `{docker} inspect {target} [--format {fmt}]`
    #[must_use]
    pub fn build_inspect_command(
        docker_bin: Option<&str>,
        target: &str,
        format: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let escaped_target = shell_escape(target);
        let mut cmd = format!("{prefix}inspect {escaped_target}");

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        cmd
    }

    /// Build a `docker exec` command.
    ///
    /// Constructs: `{docker} exec [-u {user}] [-w {workdir}]
    /// [-e {K=V}]... {container} sh -c {command}`
    #[must_use]
    pub fn build_exec_command(
        docker_bin: Option<&str>,
        container: &str,
        command: &str,
        user: Option<&str>,
        workdir: Option<&str>,
        env: Option<&[String]>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let mut cmd = format!("{prefix}exec");

        if let Some(u) = user {
            let _ = write!(cmd, " -u {}", shell_escape(u));
        }

        if let Some(w) = workdir {
            let _ = write!(cmd, " -w {}", shell_escape(w));
        }

        if let Some(env_vars) = env {
            for var in env_vars {
                let _ = write!(cmd, " -e {}", shell_escape(var));
            }
        }

        let _ = write!(
            cmd,
            " {} sh -c {}",
            shell_escape(container),
            shell_escape(command)
        );

        cmd
    }

    /// Build a `docker images` command.
    ///
    /// Constructs: `{docker} images [--all] [--filter {f}] [--format {fmt}]`
    #[must_use]
    pub fn build_images_command(
        docker_bin: Option<&str>,
        all: bool,
        filter: Option<&str>,
        format: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let mut cmd = format!("{prefix}images");

        if all {
            cmd.push_str(" --all");
        }

        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        cmd
    }

    /// Build a `docker stats` command.
    ///
    /// Constructs: `{docker} stats [--no-stream] [--format {fmt}] [containers...]`
    ///
    /// Default `no_stream=true` since MCP calls should not block.
    #[must_use]
    pub fn build_stats_command(
        docker_bin: Option<&str>,
        containers: Option<&[String]>,
        no_stream: bool,
        format: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let mut cmd = format!("{prefix}stats");

        if no_stream {
            cmd.push_str(" --no-stream");
        }

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        if let Some(ctrs) = containers {
            for c in ctrs {
                let _ = write!(cmd, " {}", shell_escape(c));
            }
        }

        cmd
    }

    /// Build a docker compose command.
    ///
    /// Constructs: `cd {project_dir} && {compose} [-f {file}] {action}
    /// [--detach] [--build] [--timeout {t}] [services...]`
    ///
    /// Action-specific flags:
    /// - `detach` and `build` only apply to `up`
    /// - `timeout` only applies to `down` and `restart`
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_compose_command(
        compose_bin: Option<&str>,
        action: &str,
        project_dir: &str,
        file: Option<&str>,
        services: Option<&[String]>,
        detach: bool,
        build: bool,
        timeout: Option<u64>,
    ) -> String {
        let prefix = docker_compose_detect_prefix(compose_bin);
        let escaped_dir = shell_escape(project_dir);
        let mut cmd = format!("cd {escaped_dir} && {prefix}");

        if let Some(f) = file {
            let _ = write!(cmd, "-f {} ", shell_escape(f));
        }

        cmd.push_str(action);

        // Action-specific flags
        if action == "up" {
            if detach {
                cmd.push_str(" --detach");
            }
            if build {
                cmd.push_str(" --build");
            }
        }

        if (action == "down" || action == "restart")
            && let Some(t) = timeout
        {
            let _ = write!(cmd, " --timeout {t}");
        }

        if let Some(svcs) = services {
            for svc in svcs {
                let _ = write!(cmd, " {}", shell_escape(svc));
            }
        }

        cmd
    }

    /// Build a `docker volume ls` command.
    ///
    /// Constructs: `{docker} volume ls [--filter {filter}] [--format {fmt}]`
    #[must_use]
    pub fn build_volume_ls_command(
        docker_bin: Option<&str>,
        filter: Option<&str>,
        format: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let mut cmd = format!("{prefix}volume ls");

        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        cmd
    }

    /// Build a `docker network ls` command.
    ///
    /// Constructs: `{docker} network ls [--filter {filter}] [--format {fmt}]`
    #[must_use]
    pub fn build_network_ls_command(
        docker_bin: Option<&str>,
        filter: Option<&str>,
        format: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let mut cmd = format!("{prefix}network ls");

        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        cmd
    }

    /// Build a `docker volume inspect` command.
    ///
    /// Constructs: `{docker} volume inspect [--format {fmt}] {volume}`
    #[must_use]
    pub fn build_volume_inspect_command(
        docker_bin: Option<&str>,
        volume: &str,
        format: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let mut cmd = format!("{prefix}volume inspect");

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        let _ = write!(cmd, " {}", shell_escape(volume));
        cmd
    }

    /// Build a `docker network inspect` command.
    ///
    /// Constructs: `{docker} network inspect [--format {fmt}] {network}`
    #[must_use]
    pub fn build_network_inspect_command(
        docker_bin: Option<&str>,
        network: &str,
        format: Option<&str>,
    ) -> String {
        let prefix = docker_detect_prefix(docker_bin);
        let mut cmd = format!("{prefix}network inspect");

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        let _ = write!(cmd, " {}", shell_escape(network));
        cmd
    }

    /// Validate a compose action.
    ///
    /// Only allows: `up`, `down`, `restart`, `ps`, `logs`, `pull`, `build`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the action is not allowed.
    pub fn validate_compose_action(action: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["up", "down", "restart", "ps", "logs", "pull", "build"];
        if ALLOWED.contains(&action) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Compose action '{}' is not allowed. Allowed actions: {}",
                    action,
                    ALLOWED.join(", ")
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── docker_detect_prefix ────────────────────────────────────────

    #[test]
    fn test_docker_detect_prefix_explicit() {
        let prefix = docker_detect_prefix(Some("podman"));
        assert_eq!(prefix, "podman ");
    }

    #[test]
    fn test_docker_detect_prefix_auto() {
        let prefix = docker_detect_prefix(None);
        assert!(prefix.contains("command -v docker"));
        assert!(prefix.contains("podman"));
        // When neither docker nor podman is found we emit a stderr message
        // and echo `false` so the outer command becomes `false ...` (exit 1)
        // rather than running the literal sentinel as a command (exit 127
        // with a confusing `command not found` message).
        assert!(prefix.contains("not installed on host"));
        assert!(prefix.contains("echo false"));
    }

    // ── docker_compose_detect_prefix ────────────────────────────────

    #[test]
    fn test_compose_detect_prefix_explicit() {
        let prefix = docker_compose_detect_prefix(Some("docker-compose"));
        assert_eq!(prefix, "docker-compose ");
    }

    #[test]
    fn test_compose_detect_prefix_auto() {
        let prefix = docker_compose_detect_prefix(None);
        assert!(prefix.contains("docker compose version"));
        assert!(prefix.contains("docker-compose"));
        assert!(prefix.contains("not installed on host"));
        assert!(prefix.contains("echo false"));
    }

    // ── build_ps_command ────────────────────────────────────────────

    #[test]
    fn test_ps_minimal() {
        let cmd = DockerCommandBuilder::build_ps_command(Some("docker"), false, None, None);
        assert_eq!(cmd, "docker ps");
    }

    #[test]
    fn test_ps_all() {
        let cmd = DockerCommandBuilder::build_ps_command(Some("docker"), true, None, None);
        assert_eq!(cmd, "docker ps --all");
    }

    #[test]
    fn test_ps_with_filter() {
        let cmd = DockerCommandBuilder::build_ps_command(
            Some("docker"),
            false,
            Some("status=running"),
            None,
        );
        assert!(cmd.contains("--filter 'status=running'"));
    }

    #[test]
    fn test_ps_with_format() {
        let cmd = DockerCommandBuilder::build_ps_command(
            Some("docker"),
            false,
            None,
            Some("{{.Names}}\t{{.Status}}"),
        );
        assert!(cmd.contains("--format"));
    }

    #[test]
    fn test_ps_all_options() {
        let cmd = DockerCommandBuilder::build_ps_command(
            Some("docker"),
            true,
            Some("name=nginx"),
            Some("json"),
        );
        assert!(cmd.contains("--all"));
        assert!(cmd.contains("--filter 'name=nginx'"));
        assert!(cmd.contains("--format 'json'"));
    }

    #[test]
    fn test_ps_auto_detect() {
        let cmd = DockerCommandBuilder::build_ps_command(None, false, None, None);
        assert!(cmd.contains("command -v docker"));
        assert!(cmd.ends_with("ps"));
    }

    // ── build_logs_command ──────────────────────────────────────────

    #[test]
    fn test_logs_minimal() {
        let cmd = DockerCommandBuilder::build_logs_command(
            Some("docker"),
            "nginx",
            None,
            None,
            None,
            false,
        );
        assert_eq!(cmd, "docker logs 'nginx'");
    }

    #[test]
    fn test_logs_with_tail() {
        let cmd = DockerCommandBuilder::build_logs_command(
            Some("docker"),
            "nginx",
            Some(100),
            None,
            None,
            false,
        );
        assert!(cmd.contains("--tail=100"));
    }

    #[test]
    fn test_logs_with_since() {
        let cmd = DockerCommandBuilder::build_logs_command(
            Some("docker"),
            "web",
            None,
            Some("1h"),
            None,
            false,
        );
        assert!(cmd.contains("--since '1h'"));
    }

    #[test]
    fn test_logs_with_until() {
        let cmd = DockerCommandBuilder::build_logs_command(
            Some("docker"),
            "web",
            None,
            None,
            Some("30m"),
            false,
        );
        assert!(cmd.contains("--until '30m'"));
    }

    #[test]
    fn test_logs_with_timestamps() {
        let cmd =
            DockerCommandBuilder::build_logs_command(Some("docker"), "web", None, None, None, true);
        assert!(cmd.contains("--timestamps"));
    }

    #[test]
    fn test_logs_all_options() {
        let cmd = DockerCommandBuilder::build_logs_command(
            Some("docker"),
            "app",
            Some(50),
            Some("2024-01-01"),
            Some("2024-06-01"),
            true,
        );
        assert!(cmd.starts_with("docker logs 'app'"));
        assert!(cmd.contains("--tail=50"));
        assert!(cmd.contains("--since '2024-01-01'"));
        assert!(cmd.contains("--until '2024-06-01'"));
        assert!(cmd.contains("--timestamps"));
    }

    #[test]
    fn test_logs_container_with_special_chars() {
        let cmd = DockerCommandBuilder::build_logs_command(
            Some("docker"),
            "my-app's-container",
            None,
            None,
            None,
            false,
        );
        assert!(cmd.contains("'my-app'\\''s-container'"));
    }

    // ── build_inspect_command ───────────────────────────────────────

    #[test]
    fn test_inspect_minimal() {
        let cmd = DockerCommandBuilder::build_inspect_command(Some("docker"), "nginx", None);
        assert_eq!(cmd, "docker inspect 'nginx'");
    }

    #[test]
    fn test_inspect_with_format() {
        let cmd = DockerCommandBuilder::build_inspect_command(
            Some("docker"),
            "nginx",
            Some("{{.State.Status}}"),
        );
        assert!(cmd.contains("--format '{{.State.Status}}'"));
    }

    #[test]
    fn test_inspect_auto_detect() {
        let cmd = DockerCommandBuilder::build_inspect_command(None, "my-container", None);
        assert!(cmd.contains("command -v docker"));
        assert!(cmd.contains("inspect 'my-container'"));
    }

    // ── build_exec_command ──────────────────────────────────────────

    #[test]
    fn test_exec_minimal() {
        let cmd = DockerCommandBuilder::build_exec_command(
            Some("docker"),
            "nginx",
            "ls -la",
            None,
            None,
            None,
        );
        assert!(cmd.starts_with("docker exec"));
        assert!(cmd.contains("'nginx' sh -c 'ls -la'"));
    }

    #[test]
    fn test_exec_with_user() {
        let cmd = DockerCommandBuilder::build_exec_command(
            Some("docker"),
            "app",
            "whoami",
            Some("root"),
            None,
            None,
        );
        assert!(cmd.contains("-u 'root'"));
    }

    #[test]
    fn test_exec_with_workdir() {
        let cmd = DockerCommandBuilder::build_exec_command(
            Some("docker"),
            "app",
            "ls",
            None,
            Some("/app"),
            None,
        );
        assert!(cmd.contains("-w '/app'"));
    }

    #[test]
    fn test_exec_with_env() {
        let env = vec!["FOO=bar".to_string(), "DEBUG=1".to_string()];
        let cmd = DockerCommandBuilder::build_exec_command(
            Some("docker"),
            "app",
            "printenv",
            None,
            None,
            Some(&env),
        );
        assert!(cmd.contains("-e 'FOO=bar'"));
        assert!(cmd.contains("-e 'DEBUG=1'"));
    }

    #[test]
    fn test_exec_all_options() {
        let env = vec!["KEY=value".to_string()];
        let cmd = DockerCommandBuilder::build_exec_command(
            Some("docker"),
            "web",
            "cat /etc/hostname",
            Some("www-data"),
            Some("/var/www"),
            Some(&env),
        );
        assert!(cmd.contains("-u 'www-data'"));
        assert!(cmd.contains("-w '/var/www'"));
        assert!(cmd.contains("-e 'KEY=value'"));
        assert!(cmd.contains("'web' sh -c 'cat /etc/hostname'"));
    }

    #[test]
    fn test_exec_command_with_quotes() {
        let cmd = DockerCommandBuilder::build_exec_command(
            Some("docker"),
            "app",
            "echo 'hello world'",
            None,
            None,
            None,
        );
        assert!(cmd.contains("sh -c 'echo '\\''hello world'\\'''"));
    }

    // ── build_images_command ────────────────────────────────────────

    #[test]
    fn test_images_minimal() {
        let cmd = DockerCommandBuilder::build_images_command(Some("docker"), false, None, None);
        assert_eq!(cmd, "docker images");
    }

    #[test]
    fn test_images_all() {
        let cmd = DockerCommandBuilder::build_images_command(Some("docker"), true, None, None);
        assert_eq!(cmd, "docker images --all");
    }

    #[test]
    fn test_images_with_filter() {
        let cmd = DockerCommandBuilder::build_images_command(
            Some("docker"),
            false,
            Some("dangling=true"),
            None,
        );
        assert!(cmd.contains("--filter 'dangling=true'"));
    }

    #[test]
    fn test_images_all_options() {
        let cmd = DockerCommandBuilder::build_images_command(
            Some("podman"),
            true,
            Some("reference=nginx:*"),
            Some("{{.Repository}}:{{.Tag}}"),
        );
        assert!(cmd.starts_with("podman images"));
        assert!(cmd.contains("--all"));
        assert!(cmd.contains("--filter 'reference=nginx:*'"));
        assert!(cmd.contains("--format"));
    }

    // ── build_stats_command ─────────────────────────────────────────

    #[test]
    fn test_stats_minimal() {
        let cmd = DockerCommandBuilder::build_stats_command(Some("docker"), None, true, None);
        assert_eq!(cmd, "docker stats --no-stream");
    }

    #[test]
    fn test_stats_stream() {
        let cmd = DockerCommandBuilder::build_stats_command(Some("docker"), None, false, None);
        assert_eq!(cmd, "docker stats");
    }

    #[test]
    fn test_stats_with_containers() {
        let containers = vec!["web".to_string(), "db".to_string()];
        let cmd = DockerCommandBuilder::build_stats_command(
            Some("docker"),
            Some(&containers),
            true,
            None,
        );
        assert!(cmd.contains("--no-stream"));
        assert!(cmd.contains("'web'"));
        assert!(cmd.contains("'db'"));
    }

    #[test]
    fn test_stats_with_format() {
        let cmd = DockerCommandBuilder::build_stats_command(
            Some("docker"),
            None,
            true,
            Some("{{.Name}}\t{{.CPUPerc}}"),
        );
        assert!(cmd.contains("--format"));
    }

    #[test]
    fn test_stats_all_options() {
        let containers = vec!["app".to_string()];
        let cmd = DockerCommandBuilder::build_stats_command(
            Some("docker"),
            Some(&containers),
            true,
            Some("table {{.Name}}\t{{.MemUsage}}"),
        );
        assert!(cmd.contains("--no-stream"));
        assert!(cmd.contains("--format"));
        assert!(cmd.contains("'app'"));
    }

    // ── build_compose_command ───────────────────────────────────────

    #[test]
    fn test_compose_up_minimal() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "up",
            "/opt/app",
            None,
            None,
            true,
            false,
            None,
        );
        assert!(cmd.starts_with("cd '/opt/app' && docker compose "));
        assert!(cmd.contains("up --detach"));
    }

    #[test]
    fn test_compose_up_with_build() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "up",
            "/opt/app",
            None,
            None,
            true,
            true,
            None,
        );
        assert!(cmd.contains("up --detach --build"));
    }

    #[test]
    fn test_compose_up_no_detach() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "up",
            "/opt/app",
            None,
            None,
            false,
            false,
            None,
        );
        assert!(cmd.contains("up"));
        assert!(!cmd.contains("--detach"));
    }

    #[test]
    fn test_compose_down() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "down",
            "/opt/app",
            None,
            None,
            false,
            false,
            None,
        );
        assert!(cmd.contains("down"));
        assert!(!cmd.contains("--detach"));
    }

    #[test]
    fn test_compose_down_with_timeout() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "down",
            "/opt/app",
            None,
            None,
            false,
            false,
            Some(30),
        );
        assert!(cmd.contains("down --timeout 30"));
    }

    #[test]
    fn test_compose_restart_with_timeout() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "restart",
            "/opt/app",
            None,
            None,
            false,
            false,
            Some(10),
        );
        assert!(cmd.contains("restart --timeout 10"));
    }

    #[test]
    fn test_compose_ps() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "ps",
            "/opt/app",
            None,
            None,
            false,
            false,
            None,
        );
        assert!(cmd.contains("ps"));
        assert!(!cmd.contains("--detach"));
        assert!(!cmd.contains("--timeout"));
    }

    #[test]
    fn test_compose_with_file() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "up",
            "/opt/app",
            Some("docker-compose.prod.yml"),
            None,
            true,
            false,
            None,
        );
        assert!(cmd.contains("-f 'docker-compose.prod.yml'"));
    }

    #[test]
    fn test_compose_with_services() {
        let services = vec!["web".to_string(), "redis".to_string()];
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "up",
            "/opt/app",
            None,
            Some(&services),
            true,
            false,
            None,
        );
        assert!(cmd.contains("'web'"));
        assert!(cmd.contains("'redis'"));
    }

    #[test]
    fn test_compose_all_options() {
        let services = vec!["api".to_string(), "worker".to_string()];
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker-compose"),
            "up",
            "/home/deploy/myapp",
            Some("compose.yaml"),
            Some(&services),
            true,
            true,
            None,
        );
        assert!(cmd.starts_with("cd '/home/deploy/myapp' && docker-compose "));
        assert!(cmd.contains("-f 'compose.yaml'"));
        assert!(cmd.contains("up --detach --build"));
        assert!(cmd.contains("'api'"));
        assert!(cmd.contains("'worker'"));
    }

    #[test]
    fn test_compose_auto_detect() {
        let cmd = DockerCommandBuilder::build_compose_command(
            None, "ps", "/opt/app", None, None, false, false, None,
        );
        assert!(cmd.contains("docker compose version"));
    }

    #[test]
    fn test_compose_project_dir_with_spaces() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "ps",
            "/opt/my app",
            None,
            None,
            false,
            false,
            None,
        );
        assert!(cmd.contains("cd '/opt/my app'"));
    }

    #[test]
    fn test_compose_detach_ignored_for_down() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "down",
            "/opt/app",
            None,
            None,
            true, // detach should be ignored
            true, // build should be ignored
            None,
        );
        assert!(!cmd.contains("--detach"));
        assert!(!cmd.contains("--build"));
    }

    #[test]
    fn test_compose_timeout_ignored_for_up() {
        let cmd = DockerCommandBuilder::build_compose_command(
            Some("docker compose"),
            "up",
            "/opt/app",
            None,
            None,
            true,
            false,
            Some(30), // timeout should be ignored for up
        );
        assert!(!cmd.contains("--timeout"));
    }

    // ── validate_compose_action ─────────────────────────────────────

    #[test]
    fn test_validate_compose_action_allowed() {
        for action in &["up", "down", "restart", "ps", "logs", "pull", "build"] {
            assert!(
                DockerCommandBuilder::validate_compose_action(action).is_ok(),
                "Action '{action}' should be allowed"
            );
        }
    }

    #[test]
    fn test_validate_compose_action_denied() {
        for action in &["rm", "kill", "exec", "run", "invalid", ""] {
            let result = DockerCommandBuilder::validate_compose_action(action);
            assert!(result.is_err(), "Action '{action}' should be denied");
            match result.unwrap_err() {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains(action));
                }
                e => panic!("Expected CommandDenied, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_validate_compose_action_case_sensitive() {
        // Actions are case-sensitive -- only lowercase is allowed
        assert!(DockerCommandBuilder::validate_compose_action("Up").is_err());
        assert!(DockerCommandBuilder::validate_compose_action("DOWN").is_err());
    }

    // ── build_volume_ls_command ──────────────────────────────────────

    #[test]
    fn test_volume_ls_minimal() {
        let cmd = DockerCommandBuilder::build_volume_ls_command(Some("docker"), None, None);
        assert_eq!(cmd, "docker volume ls");
    }

    #[test]
    fn test_volume_ls_with_filter() {
        let cmd = DockerCommandBuilder::build_volume_ls_command(
            Some("docker"),
            Some("dangling=true"),
            None,
        );
        assert!(cmd.contains("--filter 'dangling=true'"));
    }

    #[test]
    fn test_volume_ls_with_format() {
        let cmd = DockerCommandBuilder::build_volume_ls_command(
            Some("docker"),
            None,
            Some("{{.Name}}\t{{.Driver}}"),
        );
        assert!(cmd.contains("--format"));
    }

    #[test]
    fn test_volume_ls_auto_detect() {
        let cmd = DockerCommandBuilder::build_volume_ls_command(None, None, None);
        assert!(cmd.contains("command -v docker"));
        assert!(cmd.contains("volume ls"));
    }

    // ── build_network_ls_command ─────────────────────────────────────

    #[test]
    fn test_network_ls_minimal() {
        let cmd = DockerCommandBuilder::build_network_ls_command(Some("docker"), None, None);
        assert_eq!(cmd, "docker network ls");
    }

    #[test]
    fn test_network_ls_with_filter() {
        let cmd = DockerCommandBuilder::build_network_ls_command(
            Some("docker"),
            Some("driver=bridge"),
            None,
        );
        assert!(cmd.contains("--filter 'driver=bridge'"));
    }

    #[test]
    fn test_network_ls_with_format() {
        let cmd = DockerCommandBuilder::build_network_ls_command(
            Some("docker"),
            None,
            Some("{{.Name}}\t{{.Driver}}"),
        );
        assert!(cmd.contains("--format"));
    }

    // ── build_volume_inspect_command ─────────────────────────────────

    #[test]
    fn test_volume_inspect_minimal() {
        let cmd =
            DockerCommandBuilder::build_volume_inspect_command(Some("docker"), "my-volume", None);
        assert_eq!(cmd, "docker volume inspect 'my-volume'");
    }

    #[test]
    fn test_volume_inspect_with_format() {
        let cmd = DockerCommandBuilder::build_volume_inspect_command(
            Some("docker"),
            "data",
            Some("{{.Mountpoint}}"),
        );
        assert!(cmd.contains("--format '{{.Mountpoint}}'"));
        assert!(cmd.contains("'data'"));
    }

    // ── build_network_inspect_command ────────────────────────────────

    #[test]
    fn test_network_inspect_minimal() {
        let cmd =
            DockerCommandBuilder::build_network_inspect_command(Some("docker"), "bridge", None);
        assert_eq!(cmd, "docker network inspect 'bridge'");
    }

    #[test]
    fn test_network_inspect_with_format() {
        let cmd = DockerCommandBuilder::build_network_inspect_command(
            Some("docker"),
            "my-net",
            Some("{{.IPAM}}"),
        );
        assert!(cmd.contains("--format '{{.IPAM}}'"));
        assert!(cmd.contains("'my-net'"));
    }

    // ── Security: Injection Prevention ────────────────────────────────

    #[test]
    fn test_docker_bin_injection_falls_back_to_autodetect() {
        let prefix = docker_detect_prefix(Some("echo pwned #"));
        assert!(prefix.contains("command -v docker"));
    }

    #[test]
    fn test_compose_bin_injection_falls_back_to_autodetect() {
        let prefix = docker_compose_detect_prefix(Some("echo pwned; rm -rf /"));
        assert!(prefix.contains("docker compose version"));
    }

    #[test]
    fn test_valid_docker_binary_paths() {
        assert!(is_valid_binary_path("docker"));
        assert!(is_valid_binary_path("podman"));
        assert!(is_valid_binary_path("/usr/bin/docker"));
        assert!(is_valid_binary_path("docker compose"));
        assert!(is_valid_binary_path("docker-compose"));
    }

    #[test]
    fn test_invalid_docker_binary_paths() {
        assert!(!is_valid_binary_path("echo pwned #"));
        assert!(!is_valid_binary_path("docker; rm -rf /"));
        assert!(!is_valid_binary_path("$(whoami)"));
        assert!(!is_valid_binary_path(""));
    }
}
