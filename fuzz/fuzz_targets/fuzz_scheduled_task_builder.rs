#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::scheduled_task::{
    validate_task_name, ScheduledTaskCommandBuilder,
};

fuzz_target!(|data: &str| {
    // validator
    let _ = validate_task_name(data);

    // list
    let cmd = ScheduledTaskCommandBuilder::build_list_command();
    assert!(
        cmd.contains("Get-ScheduledTask"),
        "list must contain 'Get-ScheduledTask': {cmd}"
    );

    // info
    let cmd = ScheduledTaskCommandBuilder::build_info_command(data);
    assert!(
        cmd.contains("Get-ScheduledTask"),
        "info must contain 'Get-ScheduledTask': {cmd}"
    );

    // run
    let cmd = ScheduledTaskCommandBuilder::build_run_command(data);
    assert!(
        cmd.contains("Start-ScheduledTask"),
        "run must contain 'Start-ScheduledTask': {cmd}"
    );

    // enable
    let cmd = ScheduledTaskCommandBuilder::build_enable_command(data);
    assert!(
        cmd.contains("Enable-ScheduledTask"),
        "enable must contain 'Enable-ScheduledTask': {cmd}"
    );

    // disable
    let cmd = ScheduledTaskCommandBuilder::build_disable_command(data);
    assert!(
        cmd.contains("Disable-ScheduledTask"),
        "disable must contain 'Disable-ScheduledTask': {cmd}"
    );
});
