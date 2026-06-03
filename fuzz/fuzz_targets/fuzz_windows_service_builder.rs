#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::windows_service::{
    validate_service_name, WindowsServiceCommandBuilder,
};

fuzz_target!(|data: (u32, &str)| {
    let (count, text) = data;

    // validator
    let _ = validate_service_name(text);

    // status
    let cmd = WindowsServiceCommandBuilder::build_status_command(text);
    assert!(cmd.contains("Get-Service"), "status must contain 'Get-Service': {cmd}");

    // start
    let cmd = WindowsServiceCommandBuilder::build_start_command(text);
    assert!(cmd.contains("Start-Service"), "start must contain 'Start-Service': {cmd}");

    // stop
    let cmd = WindowsServiceCommandBuilder::build_stop_command(text);
    assert!(cmd.contains("Stop-Service"), "stop must contain 'Stop-Service': {cmd}");

    // restart
    let cmd = WindowsServiceCommandBuilder::build_restart_command(text);
    assert!(cmd.contains("Restart-Service"), "restart must contain 'Restart-Service': {cmd}");

    // list
    let cmd = WindowsServiceCommandBuilder::build_list_command();
    assert!(cmd.contains("Get-Service"), "list must contain 'Get-Service': {cmd}");

    // enable
    let cmd = WindowsServiceCommandBuilder::build_enable_command(text);
    assert!(cmd.contains("Set-Service"), "enable must contain 'Set-Service': {cmd}");

    // disable
    let cmd = WindowsServiceCommandBuilder::build_disable_command(text);
    assert!(cmd.contains("Set-Service"), "disable must contain 'Set-Service': {cmd}");

    // config
    let cmd = WindowsServiceCommandBuilder::build_config_command(text);
    assert!(cmd.contains("Get-Service"), "config must contain 'Get-Service': {cmd}");

    // event_logs
    let cmd = WindowsServiceCommandBuilder::build_event_logs_command(text, count);
    assert!(
        cmd.contains("Get-WinEvent") || cmd.contains("Get-EventLog"),
        "event_logs must contain event cmdlet: {cmd}"
    );
});
