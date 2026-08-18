#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use bridge_mcp::HelmCommandBuilder;

fuzz_target!(|data: &str| {
    // Fuzz all 7 HelmCommandBuilder methods with arbitrary strings.
    // Invariant: output must always contain "helm" and never panic.
    //
    // Every `Option<&str>` and `&str` parameter is fed the fuzzed input:
    // these are the ones that reach a shell command, so they are the ones
    // worth exploring. Booleans and numeric parameters are pinned, since a
    // bool has no interesting input space and the numeric ones are typed.

    let mut set_vals = HashMap::new();
    set_vals.insert(data.to_string(), data.to_string());
    let values_files = vec![data.to_string()];

    // 1. build_list_command
    let cmd = HelmCommandBuilder::build_list_command(
        Some("helm"),
        Some(data), // kubeconfig
        Some(data), // namespace
        true,       // all_namespaces
        true,       // all
        Some(data), // filter
        Some(data), // output
        true,       // failed
        true,       // pending
        Some(data), // selector
        Some(25),   // max
    );
    assert!(cmd.contains("helm"), "list must contain 'helm': {cmd}");

    // 2. build_status_command
    let cmd = HelmCommandBuilder::build_status_command(
        Some("helm"),
        Some(data), // kubeconfig
        data,       // release
        Some(data), // namespace
        Some(data), // output
        Some(42),   // revision
        true,       // show_resources
        true,       // show_desc
    );
    assert!(cmd.contains("helm"), "status must contain 'helm': {cmd}");

    // 3. build_upgrade_command
    let cmd = HelmCommandBuilder::build_upgrade_command(
        Some("helm"),
        Some(data),                    // kubeconfig
        data,                          // release
        data,                          // chart
        Some(data),                    // namespace
        Some(&set_vals),               // set_values
        Some(values_files.as_slice()), // values_files
        Some(data),                    // dry_run
        true,                          // wait
        Some(data),                    // timeout
        true,                          // install
        Some(data),                    // version
        true,                          // create_namespace
        true,                          // atomic
        true,                          // reuse_values
        Some(&set_vals),               // set_string
        true,                          // wait_for_jobs
    );
    assert!(cmd.contains("helm"), "upgrade must contain 'helm': {cmd}");

    // 4. build_install_command
    let cmd = HelmCommandBuilder::build_install_command(
        Some("helm"),
        Some(data),                    // kubeconfig
        data,                          // release
        data,                          // chart
        Some(data),                    // namespace
        Some(&set_vals),               // set_values
        Some(values_files.as_slice()), // values_files
        Some(data),                    // dry_run
        true,                          // wait
        true,                          // create_namespace
        Some(data),                    // version
        true,                          // atomic
        Some(&set_vals),               // set_string
        true,                          // wait_for_jobs
        Some(data),                    // timeout
    );
    assert!(cmd.contains("helm"), "install must contain 'helm': {cmd}");

    // 5. build_rollback_command
    let cmd = HelmCommandBuilder::build_rollback_command(
        Some("helm"),
        Some(data), // kubeconfig
        data,       // release
        Some(10),   // revision
        Some(data), // namespace
        Some(data), // dry_run
        true,       // wait
        true,       // cleanup_on_fail
        true,       // wait_for_jobs
        Some(data), // timeout
        true,       // force
    );
    assert!(cmd.contains("helm"), "rollback must contain 'helm': {cmd}");

    // 6. build_history_command
    let cmd = HelmCommandBuilder::build_history_command(
        Some("helm"),
        Some(data), // kubeconfig
        data,       // release
        Some(data), // namespace
        Some(data), // output
    );
    assert!(cmd.contains("helm"), "history must contain 'helm': {cmd}");

    // 7. build_uninstall_command
    let cmd = HelmCommandBuilder::build_uninstall_command(
        Some("helm"),
        Some(data), // kubeconfig
        data,       // release
        Some(data), // namespace
        true,       // dry_run
        true,       // keep_history
        true,       // no_hooks
        true,       // wait
        Some(data), // cascade
        Some(data), // timeout
    );
    assert!(cmd.contains("helm"), "uninstall must contain 'helm': {cmd}");

    // Also test with auto-detect (None helm_bin) and everything else empty.
    let cmd = HelmCommandBuilder::build_list_command(
        None, None, None, false, false, None, None, false, false, None, None,
    );
    assert!(cmd.contains("helm"), "auto-detect must reference helm");
});
