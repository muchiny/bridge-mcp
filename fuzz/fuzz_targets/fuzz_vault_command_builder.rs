#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::vault::{validate_vault_path, VaultCommandBuilder};

fuzz_target!(|data: &str| {
    let kv_data = vec![data.to_string()];

    // validate_vault_path
    let _ = validate_vault_path(data);

    // status
    let cmd = VaultCommandBuilder::build_status_command(Some(data), Some(data));
    assert!(cmd.contains("vault"), "status must contain 'vault': {cmd}");

    // read
    if let Ok(cmd) =
        VaultCommandBuilder::build_read_command(data, Some(data), Some(data), Some(data), Some(data))
    {
        assert!(cmd.contains("vault"), "read must contain 'vault': {cmd}");
    }

    // list
    if let Ok(cmd) =
        VaultCommandBuilder::build_list_command(data, Some(data), Some(data), Some(data))
    {
        assert!(cmd.contains("vault"), "list must contain 'vault': {cmd}");
    }

    // write
    if let Ok(cmd) =
        VaultCommandBuilder::build_write_command(data, &kv_data, Some(data), Some(data))
    {
        assert!(cmd.contains("vault"), "write must contain 'vault': {cmd}");
    }
});
