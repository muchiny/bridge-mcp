#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::KubernetesCommandBuilder;

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
    assert!(cmd.contains("kubectl"), "get must contain 'kubectl': {cmd}");

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
    assert!(cmd.contains("kubectl"), "logs must contain 'kubectl': {cmd}");

    // 3. build_describe_command
    let cmd = KubernetesCommandBuilder::build_describe_command(
        Some("kubectl"),
        data,       // resource
        Some(data), // name
        Some(data), // namespace
        None,       // label_selector
        false,      // all_namespaces
    );
    assert!(cmd.contains("kubectl"), "describe must contain 'kubectl': {cmd}");

    // 4. build_apply_command
    let cmd = KubernetesCommandBuilder::build_apply_command(
        Some("kubectl"),
        data,       // manifest
        Some(data), // namespace
        Some(data), // dry_run
        true,       // force
        true,       // server_side
    );
    assert!(cmd.contains("kubectl"), "apply must contain 'kubectl': {cmd}");

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
    assert!(cmd.contains("kubectl"), "delete must contain 'kubectl': {cmd}");

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
    assert!(cmd.contains("kubectl"), "rollout must contain 'kubectl': {cmd}");

    // 7. build_scale_command
    let cmd = KubernetesCommandBuilder::build_scale_command(
        Some("kubectl"),
        data,       // resource
        3,          // replicas
        Some(data), // namespace
    );
    assert!(cmd.contains("kubectl"), "scale must contain 'kubectl': {cmd}");

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
    assert!(cmd.contains("kubectl"), "exec must contain 'kubectl': {cmd}");

    // 9. build_top_command
    let cmd = KubernetesCommandBuilder::build_top_command(
        Some("kubectl"),
        data,       // resource_type
        Some(data), // namespace
        Some(data), // sort_by
        true,       // containers
    );
    assert!(cmd.contains("kubectl"), "top must contain 'kubectl': {cmd}");

    // Also test with auto-detect (None kubectl_bin)
    let cmd = KubernetesCommandBuilder::build_get_command(
        None, data, None, None, false, None, None, None, None, false, false, false, None,
    );
    assert!(cmd.contains("kubectl") || cmd.contains("k3s") || cmd.contains("microk8s"),
        "auto-detect must reference kubectl/k3s/microk8s");
});
