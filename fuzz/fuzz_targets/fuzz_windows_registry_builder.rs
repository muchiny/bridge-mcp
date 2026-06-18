#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::windows_registry::{
    validate_file_path, validate_registry_name, validate_registry_path,
    WindowsRegistryCommandBuilder,
};

fuzz_target!(|data: &str| {
    // validators
    let _ = validate_registry_path(data);
    let _ = validate_registry_name(data);
    let _ = validate_file_path(data);

    // query
    let cmd = WindowsRegistryCommandBuilder::query(data, Some(data));
    assert!(
        cmd.contains("Get-ItemProperty") || cmd.contains("Get-Item"),
        "query must contain registry cmdlet: {cmd}"
    );

    // query without name
    let cmd = WindowsRegistryCommandBuilder::query(data, None);
    assert!(
        cmd.contains("Get-ItemProperty") || cmd.contains("Get-Item"),
        "query (no name) must contain registry cmdlet: {cmd}"
    );

    // set_value
    let cmd = WindowsRegistryCommandBuilder::set_value(data, data, data, Some(data));
    assert!(
        cmd.contains("Set-ItemProperty") || cmd.contains("New-ItemProperty"),
        "set_value must contain registry cmdlet: {cmd}"
    );

    // set_value without type
    let cmd = WindowsRegistryCommandBuilder::set_value(data, data, data, None);
    assert!(
        cmd.contains("Set-ItemProperty") || cmd.contains("New-ItemProperty"),
        "set_value (no type) must contain registry cmdlet: {cmd}"
    );

    // list
    let cmd = WindowsRegistryCommandBuilder::list(data);
    assert!(
        cmd.contains("Get-ChildItem") || cmd.contains("Get-Item"),
        "list must contain registry cmdlet: {cmd}"
    );

    // export_key
    let cmd = WindowsRegistryCommandBuilder::export_key(data, data);
    assert!(
        cmd.contains("reg") || cmd.contains("Export"),
        "export_key must contain reg/Export: {cmd}"
    );

    // delete_property
    let cmd = WindowsRegistryCommandBuilder::delete_property(data, data);
    assert!(
        cmd.contains("Remove-ItemProperty"),
        "delete_property must contain 'Remove-ItemProperty': {cmd}"
    );
});
