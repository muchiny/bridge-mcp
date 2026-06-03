#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::systemd::{validate_service_name, SystemdCommandBuilder};

fuzz_target!(|data: &str| {
    // validators
    let _ = validate_service_name(data);
    let _ = SystemdCommandBuilder::validate_restart_action(data);

    // status
    let cmd = SystemdCommandBuilder::build_status_command(data);
    assert!(cmd.contains("systemctl"), "status must contain 'systemctl': {cmd}");

    // start
    let cmd = SystemdCommandBuilder::build_start_command(data);
    assert!(cmd.contains("systemctl"), "start must contain 'systemctl': {cmd}");

    // stop
    let cmd = SystemdCommandBuilder::build_stop_command(data);
    assert!(cmd.contains("systemctl"), "stop must contain 'systemctl': {cmd}");

    // restart (may fail validation)
    let _ = SystemdCommandBuilder::build_restart_command(data, data);

    // enable
    let cmd = SystemdCommandBuilder::build_enable_command(data);
    assert!(cmd.contains("systemctl"), "enable must contain 'systemctl': {cmd}");

    // disable
    let cmd = SystemdCommandBuilder::build_disable_command(data);
    assert!(cmd.contains("systemctl"), "disable must contain 'systemctl': {cmd}");

    // daemon-reload
    let cmd = SystemdCommandBuilder::build_daemon_reload_command();
    assert_eq!(cmd, "systemctl daemon-reload");

    // list
    let cmd = SystemdCommandBuilder::build_list_command(Some(data), true, Some(data));
    assert!(cmd.contains("systemctl"), "list must contain 'systemctl': {cmd}");

    // logs
    let cmd = SystemdCommandBuilder::build_logs_command(
        data,
        Some(100),
        Some(data),
        Some(data),
        Some(data),
        Some(data),
        true,
    );
    assert!(cmd.contains("journalctl"), "logs must contain 'journalctl': {cmd}");
});
