#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use bridge_mcp::HelmCommandBuilder;

fuzz_target!(|data: &str| {
    // Fuzz all 7 HelmCommandBuilder methods with arbitrary strings.
    // Invariant: output must always contain "helm" and never panic.

    // 1. build_list_command
    let cmd = HelmCommandBuilder::build_list_command(
        Some("helm"),
        Some(data), // namespace
        true,       // all_namespaces
        true,       // all
        Some(data), // filter
        Some(data), // output
    );
    assert!(cmd.contains("helm"), "list must contain 'helm': {cmd}");

    // 2. build_status_command
    let cmd = HelmCommandBuilder::build_status_command(
        Some("helm"),
        data,       // release
        Some(data), // namespace
        Some(data), // output
        Some(42),   // revision
    );
    assert!(cmd.contains("helm"), "status must contain 'helm': {cmd}");

    // 3. build_upgrade_command
    let mut set_vals = HashMap::new();
    set_vals.insert(data.to_string(), data.to_string());
    let values_files = vec![data.to_string()];
    let cmd = HelmCommandBuilder::build_upgrade_command(
        Some("helm"),
        data,                    // release
        data,                    // chart
        Some(data),              // namespace
        Some(&set_vals),         // set_values
        Some(values_files.as_slice()), // values_files
        Some(data),              // dry_run
        true,                    // wait
        Some(data),              // timeout
        true,                    // install
        Some(data),              // version
        true,                    // create_namespace
    );
    assert!(cmd.contains("helm"), "upgrade must contain 'helm': {cmd}");

    // 4. build_install_command
    let cmd = HelmCommandBuilder::build_install_command(
        Some("helm"),
        data,                    // release
        data,                    // chart
        Some(data),              // namespace
        Some(&set_vals),         // set_values
        Some(values_files.as_slice()), // values_files
        Some(data),              // dry_run
        true,                    // wait
        true,                    // create_namespace
        Some(data),              // version
    );
    assert!(cmd.contains("helm"), "install must contain 'helm': {cmd}");

    // 5. build_rollback_command
    let cmd = HelmCommandBuilder::build_rollback_command(
        Some("helm"),
        data,       // release
        Some(10),   // revision
        Some(data), // namespace
        Some(data), // dry_run
        true,       // wait
    );
    assert!(cmd.contains("helm"), "rollback must contain 'helm': {cmd}");

    // 6. build_history_command
    let cmd = HelmCommandBuilder::build_history_command(
        Some("helm"),
        data,       // release
        Some(data), // namespace
        Some(data), // output
    );
    assert!(cmd.contains("helm"), "history must contain 'helm': {cmd}");

    // 7. build_uninstall_command
    let cmd = HelmCommandBuilder::build_uninstall_command(
        Some("helm"),
        data,       // release
        Some(data), // namespace
        true,       // dry_run
        true,       // keep_history
    );
    assert!(cmd.contains("helm"), "uninstall must contain 'helm': {cmd}");

    // Also test with auto-detect (None helm_bin)
    let cmd = HelmCommandBuilder::build_list_command(
        None, None, false, false, None, None,
    );
    assert!(cmd.contains("helm"), "auto-detect must reference helm");
});
