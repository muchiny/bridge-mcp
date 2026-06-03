#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::hyperv::{
    validate_snapshot_name, validate_vm_name, HyperVCommandBuilder,
};

fuzz_target!(|data: &str| {
    // validators
    let _ = validate_vm_name(data);
    let _ = validate_snapshot_name(data);

    // vm_list
    let cmd = HyperVCommandBuilder::vm_list();
    assert!(cmd.contains("Get-VM"), "vm_list must contain 'Get-VM': {cmd}");

    // vm_info
    let cmd = HyperVCommandBuilder::vm_info(data);
    assert!(cmd.contains("Get-VM"), "vm_info must contain 'Get-VM': {cmd}");

    // vm_start
    let cmd = HyperVCommandBuilder::vm_start(data);
    assert!(cmd.contains("Start-VM"), "vm_start must contain 'Start-VM': {cmd}");

    // vm_stop (force=false)
    let cmd = HyperVCommandBuilder::vm_stop(data, false);
    assert!(cmd.contains("Stop-VM"), "vm_stop must contain 'Stop-VM': {cmd}");

    // vm_stop (force=true)
    let cmd = HyperVCommandBuilder::vm_stop(data, true);
    assert!(cmd.contains("Stop-VM"), "vm_stop (force) must contain 'Stop-VM': {cmd}");

    // snapshot_list
    let cmd = HyperVCommandBuilder::snapshot_list(data);
    assert!(
        cmd.contains("Get-VMSnapshot"),
        "snapshot_list must contain 'Get-VMSnapshot': {cmd}"
    );

    // snapshot_create
    let cmd = HyperVCommandBuilder::snapshot_create(data, data);
    assert!(
        cmd.contains("Checkpoint-VM"),
        "snapshot_create must contain 'Checkpoint-VM': {cmd}"
    );

    // host_info
    let cmd = HyperVCommandBuilder::host_info();
    assert!(cmd.contains("Get-VMHost"), "host_info must contain 'Get-VMHost': {cmd}");

    // switch_list
    let cmd = HyperVCommandBuilder::switch_list();
    assert!(
        cmd.contains("Get-VMSwitch"),
        "switch_list must contain 'Get-VMSwitch': {cmd}"
    );
});
