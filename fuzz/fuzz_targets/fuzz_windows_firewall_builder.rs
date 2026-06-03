#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::windows_firewall::{
    validate_firewall_rule_name, WindowsFirewallCommandBuilder,
};

fuzz_target!(|data: (u16, &str)| {
    let (port, text) = data;

    // validator
    let _ = validate_firewall_rule_name(text);

    // status
    let cmd = WindowsFirewallCommandBuilder::build_status_command();
    assert!(
        cmd.contains("Get-NetFirewallProfile"),
        "status must contain 'Get-NetFirewallProfile': {cmd}"
    );

    // list
    let cmd = WindowsFirewallCommandBuilder::build_list_command();
    assert!(
        cmd.contains("Get-NetFirewallRule"),
        "list must contain 'Get-NetFirewallRule': {cmd}"
    );

    // allow
    let cmd = WindowsFirewallCommandBuilder::build_allow_command(text, port, text);
    assert!(
        cmd.contains("New-NetFirewallRule"),
        "allow must contain 'New-NetFirewallRule': {cmd}"
    );

    // deny
    let cmd = WindowsFirewallCommandBuilder::build_deny_command(text, port, text);
    assert!(
        cmd.contains("New-NetFirewallRule"),
        "deny must contain 'New-NetFirewallRule': {cmd}"
    );

    // remove
    let cmd = WindowsFirewallCommandBuilder::build_remove_command(text);
    assert!(
        cmd.contains("Remove-NetFirewallRule"),
        "remove must contain 'Remove-NetFirewallRule': {cmd}"
    );
});
