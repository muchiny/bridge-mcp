#![no_main]

use std::collections::HashMap;

use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::HelmCommandBuilder;

// This target used to assert only the PROGRAM NAME: `assert!(cmd.contains(
// "helm"))`. That is a string the builder writes itself, in every branch,
// whatever the caller passed — so NO INPUT COULD EVER FAIL IT. A builder that
// pastes `data` into the command line in bare does not panic and does not drop
// the program name; it produces a dangerous command and the target stays
// green. An echo, not a property.
//
// What it asserts now: whatever the builder ACCEPTED arrives in the command as
// TEXT — inside one literal run, having contributed no shell syntax. Refusal
// is always fine; the fuzzer is looking for values that get THROUGH.
//
// `assert_arrives_as_text` rather than `assert_survives_as_one_word`: these
// builders emit pipelines and `&&` chains of their own, and an oracle that
// refuses every operator would be red on healthy code. It is `contains` on the
// literal run rather than equality because a value legitimately lands inside a
// larger word (`--filter=name=VALUE`); an operator still splits the run either
// way, which is what the assertion is for.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_helm_command_builder -- -dict=fuzz/dicts/shell.dict`

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
    assert_arrives_as_text(&cmd, data, "list");

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
    assert_arrives_as_text(&cmd, data, "status");

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
    assert_arrives_as_text(&cmd, data, "upgrade");

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
    assert_arrives_as_text(&cmd, data, "install");

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
    assert_arrives_as_text(&cmd, data, "rollback");

    // 6. build_history_command
    let cmd = HelmCommandBuilder::build_history_command(
        Some("helm"),
        Some(data), // kubeconfig
        data,       // release
        Some(data), // namespace
        Some(data), // output
    );
    assert_arrives_as_text(&cmd, data, "history");

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
    assert_arrives_as_text(&cmd, data, "uninstall");

    // Also test with auto-detect (None helm_bin) and everything else empty.
    let cmd = HelmCommandBuilder::build_list_command(
        None, None, None, false, false, None, None, false, false, None, None,
    );
    assert!(cmd.contains("helm"), "auto-detect must reference helm");
});
