//! Default-policy oracle for command builders.
//!
//! Every command a `build_*_command()` emits is run through the SAME gate the
//! runtime uses for built-in handlers — `CommandValidator::validate_builtin`
//! under `SecurityConfig::default()` — and must be accepted.
//!
//! This is the test that was missing before the 2026-08-31 live-host sweep:
//! 43 builders wrote `&>/dev/null`, every one of them had a test asserting
//! the emitted string, and none of those tests asked the only question that
//! matters — "does the default blacklist let this through?". It did not
//! (`>\s*/dev/` matched), so 43 tools were denied under a default config and
//! nothing in CI noticed. The tests checked what the code did, not what was
//! correct.
//!
//! The oracle here is not a hand-written expected string but a second,
//! independent component (the validator). A builder can only pass by agreeing
//! with the policy, not by agreeing with itself.
//!
//! Adding a builder: add one line to `BUILT_COMMANDS`. Realistic arguments,
//! not `""` — the point is to exercise the shape the tool emits in practice.

use bridge_mcp::config::SecurityConfig;
use bridge_mcp::domain::use_cases::{
    crictl::CrictlCommandBuilder, cron::CronCommandBuilder, docker::DockerCommandBuilder,
    firewall::FirewallCommandBuilder, journald::JournaldCommandBuilder,
    kubernetes::KubernetesCommandBuilder, package::PackageCommandBuilder,
    process::ProcessCommandBuilder, systemd::SystemdCommandBuilder,
};
use bridge_mcp::security::CommandValidator;

/// (label, command) for every builder shape that must be ACCEPTED by the
/// default policy.
///
/// Not here on purpose: `systemd_stop` and `systemd_disable`. The default
/// blacklist carries `systemctl (stop|disable|isolate)`, so those two tools
/// are refused under a default config by design — see
/// `builders_denied_by_default_are_the_documented_ones` below, which pins
/// that list so it cannot grow silently. Labels name the MCP tool so a failure reads like a bug
/// report, not a stack trace.
fn built_commands() -> Vec<(&'static str, String)> {
    vec![
        // systemd — the group that was fully unreachable on the K3s host
        (
            "systemd_status",
            SystemdCommandBuilder::build_status_command("k3s"),
        ),
        (
            "systemd_start",
            SystemdCommandBuilder::build_start_command("k3s"),
        ),
        (
            "systemd_restart",
            SystemdCommandBuilder::build_restart_command("k3s", "restart").unwrap(),
        ),
        (
            "systemd_enable",
            SystemdCommandBuilder::build_enable_command("k3s"),
        ),
        (
            "systemd_daemon_reload",
            SystemdCommandBuilder::build_daemon_reload_command(),
        ),
        (
            "systemd_list",
            SystemdCommandBuilder::build_list_command(Some("failed"), true, Some("service"))
                .unwrap(),
        ),
        (
            "systemd_logs",
            SystemdCommandBuilder::build_logs_command(
                "k3s",
                Some(200),
                Some("-1h"),
                None,
                Some("err"),
                Some("short"),
                true,
            ),
        ),
        // journald
        (
            "journald_query",
            JournaldCommandBuilder::build_query_command(
                Some("k3s"),
                Some("warning"),
                Some("yesterday"),
                None,
                Some(500),
                Some("oom"),
                true,
            ),
        ),
        (
            "journald_follow",
            JournaldCommandBuilder::build_follow_command(Some("k3s"), Some(50)),
        ),
        (
            "journald_boots",
            JournaldCommandBuilder::build_boots_command(),
        ),
        (
            "journald_disk_usage",
            JournaldCommandBuilder::build_disk_usage_command(),
        ),
        // cri — the whole group was denied before the sweep
        (
            "cri_pods",
            CrictlCommandBuilder::build_pods_command(
                None,
                Some("ready"),
                None,
                Some("app=nginx"),
                Some("default"),
                Some("json"),
            ),
        ),
        (
            "cri_stats",
            CrictlCommandBuilder::build_stats_command(None, true, None, Some("json")),
        ),
        (
            "cri_images",
            CrictlCommandBuilder::build_images_command(None, Some("json")),
        ),
        (
            "cri_info",
            CrictlCommandBuilder::build_info_command(None, Some("json")),
        ),
        (
            "cri_logs",
            CrictlCommandBuilder::build_logs_command(
                None,
                "abc123",
                Some(100),
                Some("1h"),
                true,
                true,
            ),
        ),
        (
            "cri_inspect",
            CrictlCommandBuilder::build_inspect_command(None, "container", "abc123", Some("json")),
        ),
        (
            "cri_rmi_prune",
            CrictlCommandBuilder::build_rmi_command(None, None, true).unwrap(),
        ),
        (
            "cri_exec",
            CrictlCommandBuilder::build_exec_command(None, "abc123", "cat /etc/hostname", true),
        ),
        (
            "cri_ps",
            CrictlCommandBuilder::build_ps_command(
                None,
                true,
                Some("running"),
                None,
                None,
                Some("json"),
            ),
        ),
        // docker
        (
            "docker_ps",
            DockerCommandBuilder::build_ps_command(
                None,
                true,
                Some("status=running"),
                Some("json"),
            ),
        ),
        (
            "docker_logs",
            DockerCommandBuilder::build_logs_command(
                None,
                "web",
                Some(100),
                Some("1h"),
                None,
                true,
            ),
        ),
        (
            "docker_inspect",
            DockerCommandBuilder::build_inspect_command(None, "web", None),
        ),
        (
            "docker_exec",
            DockerCommandBuilder::build_exec_command(
                None,
                "web",
                "ls -la /app",
                Some("app"),
                Some("/app"),
                None,
            ),
        ),
        (
            "docker_images",
            DockerCommandBuilder::build_images_command(None, true, None, None),
        ),
        (
            "docker_stats",
            DockerCommandBuilder::build_stats_command(None, None, true, None),
        ),
        (
            "docker_compose_up",
            DockerCommandBuilder::build_compose_command(
                None,
                "up",
                "/srv/app",
                None,
                None,
                true,
                false,
                Some(30),
            ),
        ),
        (
            "docker_volume_ls",
            DockerCommandBuilder::build_volume_ls_command(None, None, None),
        ),
        (
            "docker_network_ls",
            DockerCommandBuilder::build_network_ls_command(None, None, None),
        ),
        // firewall — also denied before the sweep
        (
            "firewall_status",
            FirewallCommandBuilder::build_status_command(None),
        ),
        (
            "firewall_list",
            FirewallCommandBuilder::build_list_command(None, Some("INPUT")),
        ),
        (
            "firewall_allow",
            FirewallCommandBuilder::build_allow_command(
                None,
                "6443",
                Some("tcp"),
                Some("10.0.0.0/8"),
            )
            .unwrap(),
        ),
        (
            "firewall_deny",
            FirewallCommandBuilder::build_deny_command(Some("ufw"), "23", Some("tcp"), None)
                .unwrap(),
        ),
        // package
        (
            "package_list",
            PackageCommandBuilder::build_list_command(None, Some("openssl")).unwrap(),
        ),
        (
            "package_search",
            PackageCommandBuilder::build_search_command(None, "curl"),
        ),
        (
            "package_install",
            PackageCommandBuilder::build_install_command(None, "jq"),
        ),
        (
            "package_remove",
            PackageCommandBuilder::build_remove_command(None, "jq"),
        ),
        (
            "package_update",
            PackageCommandBuilder::build_update_command(None, None),
        ),
        // cron
        (
            "cron_list",
            CronCommandBuilder::build_list_command(Some("pi"), true),
        ),
        (
            "cron_add",
            CronCommandBuilder::build_add_command(
                "0 3 * * *",
                "/usr/local/bin/backup.sh",
                Some("pi"),
                Some("nightly backup"),
            )
            .unwrap(),
        ),
        (
            "cron_remove",
            CronCommandBuilder::build_remove_command("backup.sh", Some("pi")),
        ),
        // process
        (
            "process_list",
            ProcessCommandBuilder::build_list_command(Some("pi"), Some("cpu"), Some("k3s")),
        ),
        (
            "process_kill",
            ProcessCommandBuilder::build_kill_command(4242, Some("TERM")).unwrap(),
        ),
        (
            "process_top",
            ProcessCommandBuilder::build_top_command(Some("mem"), None, Some(20)),
        ),
        // kubernetes — representative shapes, not the whole surface
        (
            "k8s_get",
            KubernetesCommandBuilder::build_get_command(
                None,
                "pods",
                None,
                Some("kube-system"),
                false,
                Some("app=traefik"),
                None,
                Some("wide"),
                None,
                false,
                true,
                false,
                Some(500),
            ),
        ),
        (
            "k8s_logs",
            KubernetesCommandBuilder::build_logs_command(
                None,
                "traefik-0",
                Some("kube-system"),
                None,
                Some(200),
                Some("10m"),
                true,
                true,
                None,
                false,
                None,
                false,
                None,
            ),
        ),
        (
            "k8s_rollout",
            KubernetesCommandBuilder::build_rollout_command(
                None,
                "restart",
                "deploy/web",
                Some("default"),
                None,
                None,
                None,
                None,
            ),
        ),
        (
            "k8s_drain",
            KubernetesCommandBuilder::build_drain_command(None, "node-1", true, true, false, None),
        ),
        (
            "k8s_cluster_info",
            KubernetesCommandBuilder::build_cluster_info_command(None, false, None),
        ),
    ]
}

/// Every builder output must pass the default blacklist through the exact
/// runtime gate for built-in handlers. One failure lists every offender, so a
/// regression that hits many builders (like `&>/dev/null` did) shows up as
/// "43 tools" and not as the first one alphabetically.
#[test]
fn every_builder_is_accepted_by_default_policy() {
    let cfg = SecurityConfig::default();
    let validator = CommandValidator::new(&cfg);

    let denied: Vec<String> = built_commands()
        .into_iter()
        .filter_map(|(label, cmd)| {
            validator
                .validate_builtin(&cmd)
                .err()
                .map(|e| format!("  {label}: {e}\n      CMD: {cmd}"))
        })
        .collect();

    assert!(
        denied.is_empty(),
        "{} builder(s) are denied under the DEFAULT security config — these \
         tools are unusable out of the box:\n{}",
        denied.len(),
        denied.join("\n")
    );
}

/// The builders the default policy refuses ON PURPOSE. Writing this test was
/// what surfaced the list: the first run of the acceptance test above failed
/// on exactly these two, which is the fail-closed behaviour CLAUDE.md
/// documents ("a blacklisted command asks for confirmation and is then
/// refused anyway"). Pinning them here means a third tool joining this club
/// is a deliberate decision, not a silent regression like the 43 builders.
#[test]
fn builders_denied_by_default_are_the_documented_ones() {
    let cfg = SecurityConfig::default();
    let validator = CommandValidator::new(&cfg);

    let denied_by_design = [
        (
            "systemd_stop",
            SystemdCommandBuilder::build_stop_command("k3s"),
        ),
        (
            "systemd_disable",
            SystemdCommandBuilder::build_disable_command("k3s"),
        ),
    ];
    for (label, cmd) in denied_by_design {
        assert!(
            validator.validate_builtin(&cmd).is_err(),
            "{label} is documented as denied under the default policy but was \
             accepted — either the blacklist lost `systemctl (stop|disable)` \
             or this list is stale.\n  CMD: {cmd}"
        );
    }
}

/// The oracle must actually be able to fail. If the default blacklist lets a
/// device write through, the test above proves nothing — this pins that the
/// same gate rejects what it is supposed to reject, with the exact shape a
/// builder regression would produce.
#[test]
fn default_policy_oracle_still_rejects_device_writes() {
    let cfg = SecurityConfig::default();
    let validator = CommandValidator::new(&cfg);

    let must_deny = [
        "systemctl status k3s > /dev/sda",
        "cat /var/log/syslog >/dev/nvme0n1",
        "dd if=/dev/zero of=/dev/mmcblk0",
        "rm -rf / --no-preserve-root",
    ];
    for cmd in must_deny {
        assert!(
            validator.validate_builtin(cmd).is_err(),
            "oracle is blind: default policy accepted {cmd:?}"
        );
    }

    // And the 2026-08-31 regression shape, which MUST be accepted: if this
    // flips, the blacklist has regressed to `>\s*/dev/` again.
    for cmd in [
        "command -v crictl >/dev/null 2>&1 && crictl ps",
        "systemctl is-active k3s 2>/dev/null",
        "docker ps >/dev/stdout",
    ] {
        assert!(
            validator.validate_builtin(cmd).is_ok(),
            "default policy denies the harmless null/stdout redirect: {cmd:?}"
        );
    }
}
