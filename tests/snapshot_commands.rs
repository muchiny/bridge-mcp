//! Snapshot tests for command builders and validation outputs.
//!
//! Uses insta to capture "golden file" snapshots of command builder outputs.
//! Any change to command formatting will be caught as a snapshot diff,
//! preventing accidental regressions.

use insta::assert_snapshot;

use bridge_mcp::domain::use_cases::{
    docker::DockerCommandBuilder,
    kubernetes::{HelmCommandBuilder, KubernetesCommandBuilder},
    systemd::SystemdCommandBuilder,
};

// ===== Docker Command Snapshots =====

#[test]
fn snapshot_docker_ps_default() {
    assert_snapshot!(DockerCommandBuilder::build_ps_command(
        Some("docker"),
        false,
        None,
        None
    ));
}

#[test]
fn snapshot_docker_ps_all_with_filter() {
    assert_snapshot!(DockerCommandBuilder::build_ps_command(
        Some("docker"),
        true,
        Some("status=running"),
        Some("table {{.Names}}\t{{.Status}}")
    ));
}

#[test]
fn snapshot_docker_logs_with_options() {
    assert_snapshot!(DockerCommandBuilder::build_logs_command(
        Some("docker"),
        "my-container",
        Some(100),
        Some("1h"),
        None,
        true
    ));
}

#[test]
fn snapshot_docker_inspect() {
    assert_snapshot!(DockerCommandBuilder::build_inspect_command(
        Some("docker"),
        "my-container",
        Some("{{.State.Status}}")
    ));
}

#[test]
fn snapshot_docker_exec() {
    assert_snapshot!(DockerCommandBuilder::build_exec_command(
        Some("docker"),
        "my-container",
        "ls -la /app",
        Some("node"),
        Some("/app"),
        None
    ));
}

#[test]
fn snapshot_docker_exec_with_env() {
    assert_snapshot!(DockerCommandBuilder::build_exec_command(
        Some("docker"),
        "my-container",
        "npm test",
        None,
        None,
        Some(&["NODE_ENV=test".to_string(), "CI=true".to_string()])
    ));
}

#[test]
fn snapshot_docker_images() {
    assert_snapshot!(DockerCommandBuilder::build_images_command(
        Some("docker"),
        true,
        Some("dangling=true"),
        None
    ));
}

#[test]
fn snapshot_docker_stats() {
    assert_snapshot!(DockerCommandBuilder::build_stats_command(
        Some("docker"),
        Some(&["web".to_string(), "db".to_string()]),
        true,
        None
    ));
}

#[test]
fn snapshot_docker_auto_detect() {
    assert_snapshot!(DockerCommandBuilder::build_ps_command(
        None, false, None, None
    ));
}

// ===== Systemd Command Snapshots =====

#[test]
fn snapshot_systemd_status() {
    assert_snapshot!(SystemdCommandBuilder::build_status_command("nginx"));
}

#[test]
fn snapshot_systemd_start() {
    assert_snapshot!(SystemdCommandBuilder::build_start_command(
        "postgresql@14-main"
    ));
}

#[test]
fn snapshot_systemd_stop() {
    assert_snapshot!(SystemdCommandBuilder::build_stop_command("docker.service"));
}

#[test]
fn snapshot_systemd_restart() {
    assert_snapshot!(SystemdCommandBuilder::build_restart_command("nginx", "restart").unwrap());
}

#[test]
fn snapshot_systemd_reload() {
    assert_snapshot!(SystemdCommandBuilder::build_restart_command("nginx", "reload").unwrap());
}

// ===== Kubernetes Command Snapshots =====

#[test]
fn snapshot_kubectl_get_pods() {
    assert_snapshot!(KubernetesCommandBuilder::build_get_command(
        Some("kubectl"),
        "pods",
        None,
        Some("default"),
        false,
        None,
        None,
        Some("wide"),
        None,
        false,
        false,
        false,
        None,
    ));
}

#[test]
fn snapshot_kubectl_get_all_namespaces() {
    assert_snapshot!(KubernetesCommandBuilder::build_get_command(
        Some("kubectl"),
        "deployments",
        None,
        None,
        true,
        Some("app=web"),
        None,
        Some("json"),
        None,
        false,
        false,
        false,
        None,
    ));
}

#[test]
fn snapshot_kubectl_logs() {
    assert_snapshot!(KubernetesCommandBuilder::build_logs_command(
        Some("kubectl"),
        "my-pod",
        Some("kube-system"),
        Some("my-container"),
        Some(100),
        Some("1h"),
        false,
        false,
        None,
        false,
        None,
        false,
        None,
    ));
}

#[test]
fn snapshot_kubectl_describe() {
    assert_snapshot!(KubernetesCommandBuilder::build_describe_command(
        Some("kubectl"),
        "pod",
        Some("my-pod"),
        Some("production"),
        None,
        false,
    ));
}

#[test]
fn snapshot_kubectl_auto_detect() {
    assert_snapshot!(KubernetesCommandBuilder::build_get_command(
        None, "nodes", None, None, false, None, None, None, None, false, false, false, None,
    ));
}

// ===== Helm Command Snapshots =====

#[test]
fn snapshot_helm_list() {
    assert_snapshot!(HelmCommandBuilder::build_list_command(
        Some("helm"),
        None,
        Some("production"),
        true,
        false,
        None,
        None,
        false,
        false,
        None,
        None,
    ));
}

#[test]
fn snapshot_helm_status() {
    assert_snapshot!(HelmCommandBuilder::build_status_command(
        Some("helm"),
        None,
        "my-release",
        Some("production"),
        None,
        None,
        false,
        false,
    ));
}

// ===== Shell Escaping Snapshots =====

#[test]
fn snapshot_shell_escape_special_chars() {
    use bridge_mcp::config::ShellType;
    use bridge_mcp::domain::use_cases::shell;

    let input = "it's a \"test\" with $var & pipe | redirect > file";

    assert_snapshot!("posix_escape", shell::escape(input, ShellType::Posix));
    assert_snapshot!("cmd_escape", shell::escape(input, ShellType::Cmd));
    assert_snapshot!(
        "powershell_escape",
        shell::escape(input, ShellType::PowerShell)
    );
}

#[test]
fn snapshot_cd_and_run_all_shells() {
    use bridge_mcp::config::ShellType;
    use bridge_mcp::domain::use_cases::shell;

    assert_snapshot!(
        "cd_posix",
        shell::cd_and_run("/var/log", "tail -f syslog", ShellType::Posix)
    );
    assert_snapshot!(
        "cd_cmd",
        shell::cd_and_run("C:\\Users\\Admin", "dir", ShellType::Cmd)
    );
    assert_snapshot!(
        "cd_powershell",
        shell::cd_and_run("C:\\Logs", "Get-Content log.txt", ShellType::PowerShell)
    );
}
