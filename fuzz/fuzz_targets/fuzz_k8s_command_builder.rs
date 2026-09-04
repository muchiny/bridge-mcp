#![no_main]

use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::KubernetesCommandBuilder;

// This target used to assert only the PROGRAM NAME: `assert!(cmd.contains(
// "the program name"))`. That is a string the builder writes itself, in every branch,
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
// `cargo +nightly fuzz run fuzz_k8s_command_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: &str| {
    // Fuzz all 9 KubernetesCommandBuilder methods with arbitrary strings.
    // Invariant: output must always contain the kubectl detection prefix
    // and must never panic.

    // 1. build_get_command
    let cmd = KubernetesCommandBuilder::build_get_command(
        Some("kubectl"),
        data,         // resource
        Some(data),   // name
        Some(data),   // namespace
        true,         // all_namespaces
        Some(data),   // label_selector
        Some(data),   // field_selector
        Some(data),   // output
        Some(data),   // sort_by
        false,        // raw
        false,        // show_labels
        false,        // show_kind
        None,         // chunk_size
    );
    assert_arrives_as_text(&cmd, data, "get");

    // 2. build_logs_command
    let cmd = KubernetesCommandBuilder::build_logs_command(
        Some("kubectl"),
        data,         // pod
        Some(data),   // namespace
        Some(data),   // container
        Some(100),    // tail
        Some(data),   // since
        true,         // previous
        true,         // timestamps
        None,         // label_selector
        false,        // all_containers
        None,         // max_log_requests
        false,        // prefix
        None,         // since_time
    );
    assert_arrives_as_text(&cmd, data, "logs");

    // 3. build_describe_command
    let cmd = KubernetesCommandBuilder::build_describe_command(
        Some("kubectl"),
        data,       // resource
        Some(data), // name
        Some(data), // namespace
        None,       // label_selector
        false,      // all_namespaces
    );
    assert_arrives_as_text(&cmd, data, "describe");

    // 4. build_apply_command
    let cmd = KubernetesCommandBuilder::build_apply_command(
        Some("kubectl"),
        data,       // manifest
        Some(data), // namespace
        Some(data), // dry_run
        true,       // force
        true,       // server_side
    );
    assert_arrives_as_text(&cmd, data, "apply");

    // 5. build_delete_command
    let cmd = KubernetesCommandBuilder::build_delete_command(
        Some("kubectl"),
        data,       // resource
        Some(data), // name
        Some(data), // namespace
        Some(30),   // grace_period
        true,       // force
        Some(data), // dry_run
        None,       // label_selector
        false,      // all
        None,       // field_selector
    );
    assert_arrives_as_text(&cmd, data, "delete");

    // 6. build_rollout_command
    let cmd = KubernetesCommandBuilder::build_rollout_command(
        Some("kubectl"),
        data,       // action
        data,       // resource
        Some(data), // namespace
        Some(5),    // to_revision
        None,       // watch
        None,       // timeout
        None,       // label_selector
    );
    assert_arrives_as_text(&cmd, data, "rollout");

    // 7. build_scale_command
    let cmd = KubernetesCommandBuilder::build_scale_command(
        Some("kubectl"),
        data,       // resource
        3,          // replicas
        Some(data), // namespace
    );
    assert_arrives_as_text(&cmd, data, "scale");

    // 8. build_exec_command
    let cmd = KubernetesCommandBuilder::build_exec_command(
        Some("kubectl"),
        data,       // pod
        Some(data), // command
        Some(data), // namespace
        Some(data), // container
        None,       // argv
        false,      // stdin
    );
    assert_arrives_as_text(&cmd, data, "exec");

    // 9. build_top_command
    let cmd = KubernetesCommandBuilder::build_top_command(
        Some("kubectl"),
        data,       // resource_type
        Some(data), // namespace
        true,       // all_namespaces
        Some(data), // sort_by
        true,       // containers
    );
    assert_arrives_as_text(&cmd, data, "top");

    // Also test with auto-detect (None kubectl_bin)
    let cmd = KubernetesCommandBuilder::build_get_command(
        None, data, None, None, false, None, None, None, None, false, false, false, None,
    );
    assert_arrives_as_text(&cmd, data, "auto-detect");
});
