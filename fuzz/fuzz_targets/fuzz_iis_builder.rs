#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::iis::{validate_site_name, IisCommandBuilder};

fuzz_target!(|data: &str| {
    // validator
    let _ = validate_site_name(data);

    // status
    let cmd = IisCommandBuilder::build_status_command();
    assert!(
        cmd.contains("Get-Website"),
        "status must contain 'Get-Website': {cmd}"
    );

    // list_sites
    let cmd = IisCommandBuilder::build_list_sites_command();
    assert!(
        cmd.contains("Get-Website"),
        "list_sites must contain 'Get-Website': {cmd}"
    );

    // list_pools
    let cmd = IisCommandBuilder::build_list_pools_command();
    assert!(
        cmd.contains("Get-IISAppPool"),
        "list_pools must contain 'Get-IISAppPool': {cmd}"
    );

    // start
    let cmd = IisCommandBuilder::build_start_command(data);
    assert!(
        cmd.contains("Start-Website"),
        "start must contain 'Start-Website': {cmd}"
    );

    // stop
    let cmd = IisCommandBuilder::build_stop_command(data);
    assert!(
        cmd.contains("Stop-Website"),
        "stop must contain 'Stop-Website': {cmd}"
    );

    // restart_pool
    let cmd = IisCommandBuilder::build_restart_pool_command(data);
    assert!(
        cmd.contains("Restart-WebAppPool"),
        "restart_pool must contain 'Restart-WebAppPool': {cmd}"
    );
});
