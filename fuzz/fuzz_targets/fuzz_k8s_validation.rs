#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::KubernetesCommandBuilder;

fuzz_target!(|data: &str| {
    // Fuzz the 3 validation methods on KubernetesCommandBuilder.
    // These are security-critical: they protect against accidental
    // deletion of system namespaces, restrict rollout actions,
    // and limit top resource types.

    // 1. validate_delete — protected namespaces must ALWAYS be rejected
    let result = KubernetesCommandBuilder::validate_delete("namespace", data);
    let lower = data.to_lowercase();
    if lower == "kube-system" || lower == "kube-public"
        || lower == "default" || lower == "kube-node-lease"
    {
        assert!(result.is_err(),
            "Protected namespace '{data}' must be rejected by validate_delete");
    }

    // Also test with "ns" (short form for namespace)
    let result = KubernetesCommandBuilder::validate_delete("ns", data);
    if lower == "kube-system" || lower == "kube-public"
        || lower == "default" || lower == "kube-node-lease"
    {
        assert!(result.is_err(),
            "Protected namespace '{data}' must be rejected with 'ns' resource type");
    }

    // Non-namespace resources should always be allowed
    let result = KubernetesCommandBuilder::validate_delete("pod", data);
    assert!(result.is_ok(), "Non-namespace resource delete must always succeed");

    // 2. validate_rollout_action — only status/restart/undo/history allowed
    let result = KubernetesCommandBuilder::validate_rollout_action(data);
    let allowed = ["status", "restart", "undo", "history"];
    if allowed.contains(&lower.as_str()) {
        assert!(result.is_ok(),
            "Allowed rollout action '{data}' must be accepted");
    } else {
        assert!(result.is_err(),
            "Unknown rollout action '{data}' must be rejected");
    }

    // 3. validate_top_resource — only pods/nodes allowed
    let result = KubernetesCommandBuilder::validate_top_resource(data);
    let allowed_top = ["pods", "nodes"];
    if allowed_top.contains(&lower.as_str()) {
        assert!(result.is_ok(),
            "Allowed top resource '{data}' must be accepted");
    } else {
        assert!(result.is_err(),
            "Unknown top resource '{data}' must be rejected");
    }
});
