#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::nginx::NginxCommandBuilder;

fuzz_target!(|data: &str| {
    // All 4 methods — just verify no panic
    let _ = NginxCommandBuilder::build_status_command(Some(data));
    let _ = NginxCommandBuilder::build_test_command(Some(data));
    let _ = NginxCommandBuilder::build_reload_command(Some(data));
    let _ = NginxCommandBuilder::build_list_sites_command(Some(data), Some(data));
});
