#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::active_directory::{
    validate_ad_identity, ActiveDirectoryCommandBuilder,
};

fuzz_target!(|data: &str| {
    // validator
    let _ = validate_ad_identity(data);

    // user_list
    let cmd = ActiveDirectoryCommandBuilder::build_user_list_command(Some(data));
    assert!(cmd.contains("Get-ADUser"), "user_list must contain 'Get-ADUser': {cmd}");

    // user_list without filter
    let cmd = ActiveDirectoryCommandBuilder::build_user_list_command(None);
    assert!(
        cmd.contains("Get-ADUser"),
        "user_list (no filter) must contain 'Get-ADUser': {cmd}"
    );

    // user_info
    let cmd = ActiveDirectoryCommandBuilder::build_user_info_command(data);
    assert!(cmd.contains("Get-ADUser"), "user_info must contain 'Get-ADUser': {cmd}");

    // group_list
    let cmd = ActiveDirectoryCommandBuilder::build_group_list_command();
    assert!(cmd.contains("Get-ADGroup"), "group_list must contain 'Get-ADGroup': {cmd}");

    // group_members
    let cmd = ActiveDirectoryCommandBuilder::build_group_members_command(data);
    assert!(
        cmd.contains("Get-ADGroupMember"),
        "group_members must contain 'Get-ADGroupMember': {cmd}"
    );

    // computer_list
    let cmd = ActiveDirectoryCommandBuilder::build_computer_list_command();
    assert!(
        cmd.contains("Get-ADComputer"),
        "computer_list must contain 'Get-ADComputer': {cmd}"
    );

    // domain_info
    let cmd = ActiveDirectoryCommandBuilder::build_domain_info_command();
    assert!(cmd.contains("Get-ADDomain"), "domain_info must contain 'Get-ADDomain': {cmd}");
});
