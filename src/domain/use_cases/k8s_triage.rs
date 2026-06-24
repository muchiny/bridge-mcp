//! K8s Triage Command Builder
//!
//! Builds composite kubectl/jq pipelines for Kubernetes triage and health
//! analysis. All pipelines guard for jq presence and use POSIX-safe
//! redirection (`>/dev/null 2>&1` not `&>/dev/null`).

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a binary path contains only safe characters.
fn is_valid_binary_path(bin: &str) -> bool {
    !bin.is_empty()
        && bin
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

/// Build the `K=...` shell variable head for kubectl binary detection.
///
/// Uses `>/dev/null 2>&1` (POSIX-safe) instead of `&>/dev/null` to avoid
/// the command blacklist.
fn kubectl_k_head(kubectl_bin: Option<&str>) -> String {
    if let Some(bin) = kubectl_bin
        && is_valid_binary_path(bin)
    {
        return format!("K=\"{bin}\"; ");
    }
    // POSIX-safe: uses >/dev/null 2>&1 not &>/dev/null
    "K=\"$(if command -v kubectl >/dev/null 2>&1; then echo kubectl; \
     elif command -v k3s >/dev/null 2>&1; then echo 'k3s kubectl'; \
     elif command -v microk8s >/dev/null 2>&1; then echo 'microk8s kubectl'; \
     else echo kubectl; fi)\"; "
        .to_string()
}

/// Validate a log tail count: must be 1..=500.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if `tail` is 0 or greater than 500.
pub fn validate_log_tail(tail: u64) -> Result<()> {
    if tail == 0 {
        return Err(BridgeError::CommandDenied {
            reason: "tail must be at least 1".to_string(),
        });
    }
    if tail > 500 {
        return Err(BridgeError::CommandDenied {
            reason: format!("tail {tail} exceeds maximum of 500"),
        });
    }
    Ok(())
}

/// Validate a resource type for `kubectl --watch`.
///
/// Allowlist: `pods`, `po`, `events`, `ev`, `deployments`, `deploy`,
/// `replicasets`, `rs`, `statefulsets`, `sts`, `daemonsets`, `ds`,
/// `jobs`, `nodes`, `no`, `services`, `svc`, `endpoints`, `pvc`,
/// `events.k8s.io`.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the resource is not in the
/// allowlist.
pub fn validate_watch_resource(resource: &str) -> Result<()> {
    let allowed = [
        "pods",
        "po",
        "events",
        "ev",
        "deployments",
        "deploy",
        "replicasets",
        "rs",
        "statefulsets",
        "sts",
        "daemonsets",
        "ds",
        "jobs",
        "nodes",
        "no",
        "services",
        "svc",
        "endpoints",
        "pvc",
        "events.k8s.io",
    ];
    let lower = resource.to_lowercase();
    if allowed.contains(&lower.as_str()) {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "watch resource '{resource}' is not in the allowlist. \
                 Allowed: {allowed:?}"
            ),
        })
    }
}

/// Validate a watch timeout: must be 1..=300 seconds.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if `secs` is 0 or greater than 300.
pub fn validate_watch_timeout(secs: u64) -> Result<()> {
    if secs == 0 {
        return Err(BridgeError::CommandDenied {
            reason: "watch_timeout_secs must be at least 1".to_string(),
        });
    }
    if secs > 300 {
        return Err(BridgeError::CommandDenied {
            reason: format!("watch_timeout_secs {secs} exceeds maximum of 300"),
        });
    }
    Ok(())
}

/// Builds composite kubectl/jq triage pipelines for Kubernetes.
pub struct K8sTriageCommandBuilder;

impl K8sTriageCommandBuilder {
    /// Build a composite triage pipeline aggregating non-running pods and
    /// warning events into a single JSON object.
    ///
    /// Constructs: binary-detect → jq guard → collect PODS + EVENTS JSON →
    /// join with jq into `{notReadyPods, warningEvents}`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `namespace` or `context` are
    /// invalid.
    pub fn build_triage_command(
        kubectl_bin: Option<&str>,
        namespace: Option<&str>,
        all_namespaces: bool,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ctx) = context {
            super::kubernetes::validate_context(ctx)?;
        }
        let k_head = kubectl_k_head(kubectl_bin);
        let ctxf = super::kubernetes::kubectl_context_flag(context);
        let scope_flag = build_scope_flag(namespace, all_namespaces)?;

        let mut cmd = String::new();
        let _ = write!(cmd, "{k_head}");
        let _ = write!(
            cmd,
            "command -v jq >/dev/null 2>&1 || \
             {{ echo 'jq not installed on host (required for triage aggregation)' >&2; exit 3; }}; "
        );
        let _ = write!(
            cmd,
            "PODS=\"$($K{ctxf} get pods{scope_flag} -o json 2>/dev/null)\"; "
        );
        let _ = write!(
            cmd,
            "EVENTS=\"$($K{ctxf} get events{scope_flag} --field-selector type=Warning -o json 2>/dev/null)\"; "
        );
        let _ = write!(
            cmd,
            "printf '%s\\n' \"$PODS\" | jq \
             --argjson ev \"$(printf '%s' \"$EVENTS\" | jq \
             '[.items[]|{{reason:.reason,object:.involvedObject.name,\
             message:.message,count:.count}}]')\" \
             '{{notReadyPods: [.items[] | select(.status.phase!=\"Running\" \
             and .status.phase!=\"Succeeded\") | \
             {{namespace:.metadata.namespace, pod:.metadata.name, \
             phase:.status.phase, \
             restarts:([.status.containerStatuses[]?.restartCount]|add // 0), \
             waiting:[.status.containerStatuses[]?|\
             select(.state.waiting!=null)|\
             {{container:.name, reason:.state.waiting.reason, \
             message:.state.waiting.message}}]}}], warningEvents: $ev}}'"
        );

        Ok(cmd)
    }

    /// Build a pipeline that finds all `CrashLoopBackOff` pods and streams their
    /// previous container logs.
    ///
    /// `tail` controls how many lines of previous logs to fetch per container
    /// (1–500). Validated by [`validate_log_tail`].
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `tail`, `namespace`, or
    /// `context` are invalid.
    pub fn build_crashloops_command(
        kubectl_bin: Option<&str>,
        namespace: Option<&str>,
        all_namespaces: bool,
        tail: u64,
        context: Option<&str>,
    ) -> Result<String> {
        validate_log_tail(tail)?;
        if let Some(ctx) = context {
            super::kubernetes::validate_context(ctx)?;
        }
        let k_head = kubectl_k_head(kubectl_bin);
        let ctxf = super::kubernetes::kubectl_context_flag(context);
        let scope_flag = build_scope_flag(namespace, all_namespaces)?;

        let mut cmd = String::new();
        let _ = write!(cmd, "{k_head}");
        let _ = write!(
            cmd,
            "command -v jq >/dev/null 2>&1 || \
             {{ echo 'jq not installed on host (required for crashloop aggregation)' >&2; exit 3; }}; "
        );
        let _ = write!(
            cmd,
            "$K{ctxf} get pods{scope_flag} -o json 2>/dev/null | \
             jq -r '.items[] | \
             select(any(.status.containerStatuses[]?; \
             .state.waiting.reason==\"CrashLoopBackOff\" \
             or .lastState.terminated.reason==\"Error\")) | \
             .metadata.namespace+\"\\t\"+.metadata.name+\"\\t\"+\
             ([.status.containerStatuses[]?|\
             select(.state.waiting.reason==\"CrashLoopBackOff\" \
             or .lastState.terminated!=null)|.name]|join(\",\"))+\"\\t\"+\
             ([.status.containerStatuses[]?.lastState.terminated.exitCode|\
             tostring]|join(\",\"))' | \
             while IFS=\"\\t\" read -r NS POD CONTS CODES; do \
             echo \"===== $NS/$POD (containers=$CONTS exitCodes=$CODES) =====\"; \
             for C in $(echo \"$CONTS\" | tr ',' ' '); do \
             echo \"--- $C (previous, tail={tail}) ---\"; \
             $K{ctxf} logs \"$POD\" -n \"$NS\" -c \"$C\" --previous --tail={tail} 2>&1 || \
             echo '(no previous logs)'; \
             done; done"
        );

        Ok(cmd)
    }

    /// Build a pipeline that lists pods that are NOT ready with per-container
    /// state detail and condition messages.
    ///
    /// `label_selector` maps to `-l <selector>` when set.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `namespace` or `context` are
    /// invalid.
    pub fn build_pod_health_command(
        kubectl_bin: Option<&str>,
        namespace: Option<&str>,
        all_namespaces: bool,
        label_selector: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ctx) = context {
            super::kubernetes::validate_context(ctx)?;
        }
        let k_head = kubectl_k_head(kubectl_bin);
        let ctxf = super::kubernetes::kubectl_context_flag(context);
        let scope_flag = build_scope_flag(namespace, all_namespaces)?;
        let sel_flag = build_sel_flag(label_selector);

        let mut cmd = String::new();
        let _ = write!(cmd, "{k_head}");
        let _ = write!(
            cmd,
            "command -v jq >/dev/null 2>&1 || \
             {{ echo 'jq not installed on host (required for pod health rollup)' >&2; exit 3; }}; "
        );
        let _ = write!(
            cmd,
            "$K{ctxf} get pods{scope_flag}{sel_flag} -o json 2>/dev/null | \
             jq '[.items[] | \
             {{namespace:.metadata.namespace, pod:.metadata.name, \
             phase:.status.phase, \
             ready:([.status.conditions[]?|select(.type==\"Ready\")|.status]|first // \"Unknown\"), \
             notReadyReasons:[.status.conditions[]?|\
             select(.status!=\"True\")|\
             {{type:.type, reason:.reason, message:.message}}], \
             containers:[.status.containerStatuses[]?|\
             {{name:.name, ready:.ready, restarts:.restartCount, \
             state:(.state|keys[0]), waitingReason:.state.waiting.reason, \
             terminatedReason:.state.terminated.reason}}]}} | \
             select(.ready!=\"True\")]'"
        );

        Ok(cmd)
    }

    /// Build a pipeline that lists Pending pods joined with their
    /// `FailedScheduling` events.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `namespace` or `context` are
    /// invalid.
    pub fn build_pending_command(
        kubectl_bin: Option<&str>,
        namespace: Option<&str>,
        all_namespaces: bool,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ctx) = context {
            super::kubernetes::validate_context(ctx)?;
        }
        let k_head = kubectl_k_head(kubectl_bin);
        let ctxf = super::kubernetes::kubectl_context_flag(context);
        let scope_flag = build_scope_flag(namespace, all_namespaces)?;

        let mut cmd = String::new();
        let _ = write!(cmd, "{k_head}");
        let _ = write!(
            cmd,
            "command -v jq >/dev/null 2>&1 || \
             {{ echo 'jq not installed on host (required for pending join)' >&2; exit 3; }}; "
        );
        let _ = write!(
            cmd,
            "PODS=\"$($K{ctxf} get pods{scope_flag} \
             --field-selector status.phase=Pending -o json 2>/dev/null)\"; "
        );
        let _ = write!(
            cmd,
            "EVENTS=\"$($K{ctxf} get events{scope_flag} \
             --field-selector reason=FailedScheduling -o json 2>/dev/null)\"; "
        );
        let _ = write!(
            cmd,
            "printf '%s\\n' \"$PODS\" | jq \
             --argjson ev \"$(printf '%s' \"$EVENTS\" | jq \
             '[.items[]|{{pod:.involvedObject.name, namespace:.involvedObject.namespace, \
             message:.message, count:.count, lastTimestamp:.lastTimestamp}}]')\" \
             '[.items[] | . as $p | \
             {{namespace:$p.metadata.namespace, pod:$p.metadata.name, \
             createdAt:$p.metadata.creationTimestamp, \
             schedulerMessages:[$ev[] | \
             select(.pod==$p.metadata.name \
             and .namespace==$p.metadata.namespace)]}}]'"
        );

        Ok(cmd)
    }

    /// Build a pipeline that lists all nodes with their Ready condition,
    /// resource pressures, and schedulability.
    ///
    /// Adds a synthetic `.problem` field (`true` when not Ready or any
    /// pressure condition is active).
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `context` is invalid.
    pub fn build_node_status_command(
        kubectl_bin: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ctx) = context {
            super::kubernetes::validate_context(ctx)?;
        }
        let k_head = kubectl_k_head(kubectl_bin);
        let ctxf = super::kubernetes::kubectl_context_flag(context);

        let mut cmd = String::new();
        let _ = write!(cmd, "{k_head}");
        let _ = write!(
            cmd,
            "command -v jq >/dev/null 2>&1 || \
             {{ echo 'jq not installed on host (required for node status rollup)' >&2; exit 3; }}; "
        );
        let _ = write!(
            cmd,
            "$K{ctxf} get nodes -o json 2>/dev/null | \
             jq '[.items[] | \
             {{node:.metadata.name, \
             ready:([.status.conditions[]|select(.type==\"Ready\")|.status]|first), \
             pressures:[.status.conditions[]|\
             select(.type|test(\"Pressure$\")) | \
             {{type:.type, status:.status}}], \
             schedulable:((.spec.unschedulable // false)|not), \
             kubeletVersion:.status.nodeInfo.kubeletVersion, \
             allocatable:{{cpu:.status.allocatable.cpu, \
             memory:.status.allocatable.memory, \
             pods:.status.allocatable.pods}}}} | \
             .problem = ((.ready!=\"True\") or \
             (any(.pressures[]; .status==\"True\")))]'"
        );

        Ok(cmd)
    }

    /// Build a `kubectl get <resource> --watch-only` pipeline with a
    /// `timeout` wrapper.
    ///
    /// Detects timeout exit code 124 and prints a friendly message.
    /// `label_selector` maps to `-l <selector>` when set.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `resource`, `watch_timeout_secs`,
    /// `namespace`, or `context` are invalid.
    pub fn build_watch_command(
        kubectl_bin: Option<&str>,
        resource: &str,
        namespace: Option<&str>,
        all_namespaces: bool,
        label_selector: Option<&str>,
        watch_timeout_secs: u64,
        context: Option<&str>,
    ) -> Result<String> {
        validate_watch_resource(resource)?;
        validate_watch_timeout(watch_timeout_secs)?;
        if let Some(ctx) = context {
            super::kubernetes::validate_context(ctx)?;
        }
        let k_head = kubectl_k_head(kubectl_bin);
        let ctxf = super::kubernetes::kubectl_context_flag(context);
        let scope_flag = build_scope_flag(namespace, all_namespaces)?;
        let sel_flag = build_sel_flag(label_selector);
        let resource_escaped = shell_escape(resource);

        let mut cmd = String::new();
        let _ = write!(cmd, "{k_head}");
        let _ = write!(
            cmd,
            "timeout {watch_timeout_secs} \
             $K{ctxf} get {resource_escaped}{scope_flag}{sel_flag} --watch-only 2>&1; \
             RC=$?; \
             if [ $RC -eq 124 ]; then \
             echo \"[watch ended: {watch_timeout_secs}s timeout reached]\"; \
             fi"
        );

        Ok(cmd)
    }
}

/// Build a namespace scope flag string (`-A`, `-n <ns>`, or `""`).
///
/// Priority: `all_namespaces=true` → `-A`; `namespace=Some(ns)` → `-n <ns>`
/// (validated); else empty string (current context namespace).
fn build_scope_flag(namespace: Option<&str>, all_namespaces: bool) -> Result<String> {
    if all_namespaces {
        Ok(" -A".to_string())
    } else if let Some(ns) = namespace {
        super::kubernetes::KubernetesCommandBuilder::validate_namespace(ns)?;
        Ok(format!(" -n {}", shell_escape(ns)))
    } else {
        Ok(String::new())
    }
}

/// Build a label selector flag (` -l <sel>` or `""`).
fn build_sel_flag(label_selector: Option<&str>) -> String {
    match label_selector {
        Some(sel) => format!(" -l {}", shell_escape(sel)),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============ validate_log_tail ============

    #[test]
    fn test_validate_log_tail_zero() {
        assert!(validate_log_tail(0).is_err());
    }

    #[test]
    fn test_validate_log_tail_max() {
        assert!(validate_log_tail(500).is_ok());
    }

    #[test]
    fn test_validate_log_tail_over_max() {
        assert!(validate_log_tail(501).is_err());
    }

    #[test]
    fn test_validate_log_tail_valid() {
        assert!(validate_log_tail(50).is_ok());
        assert!(validate_log_tail(1).is_ok());
    }

    // ============ validate_watch_resource ============

    #[test]
    fn test_validate_watch_resource_allowed() {
        assert!(validate_watch_resource("pods").is_ok());
        assert!(validate_watch_resource("po").is_ok());
        assert!(validate_watch_resource("events").is_ok());
        assert!(validate_watch_resource("deployments").is_ok());
        assert!(validate_watch_resource("events.k8s.io").is_ok());
    }

    #[test]
    fn test_validate_watch_resource_case_insensitive() {
        assert!(validate_watch_resource("Pods").is_ok());
        assert!(validate_watch_resource("PODS").is_ok());
    }

    #[test]
    fn test_validate_watch_resource_denied() {
        assert!(validate_watch_resource("secrets").is_err());
        assert!(validate_watch_resource("configmaps").is_err());
        assert!(validate_watch_resource("anything-else").is_err());
    }

    // ============ validate_watch_timeout ============

    #[test]
    fn test_validate_watch_timeout_zero() {
        assert!(validate_watch_timeout(0).is_err());
    }

    #[test]
    fn test_validate_watch_timeout_max() {
        assert!(validate_watch_timeout(300).is_ok());
    }

    #[test]
    fn test_validate_watch_timeout_over_max() {
        assert!(validate_watch_timeout(301).is_err());
    }

    #[test]
    fn test_validate_watch_timeout_valid() {
        assert!(validate_watch_timeout(30).is_ok());
        assert!(validate_watch_timeout(1).is_ok());
    }

    // ============ build_triage_command ============

    #[test]
    fn test_build_triage_command_with_kubectl() {
        let cmd = K8sTriageCommandBuilder::build_triage_command(Some("kubectl"), None, false, None)
            .unwrap();
        assert!(cmd.contains("K=\"kubectl\""), "cmd: {cmd}");
        assert!(cmd.contains("jq not installed"), "cmd: {cmd}");
        assert!(cmd.contains("notReadyPods"), "cmd: {cmd}");
        assert!(cmd.contains("warningEvents"), "cmd: {cmd}");
        assert!(
            !cmd.contains("&>/dev/null"),
            "must not use &>/dev/null blacklisted: {cmd}"
        );
    }

    #[test]
    fn test_build_triage_command_with_namespace() {
        let cmd = K8sTriageCommandBuilder::build_triage_command(
            Some("kubectl"),
            Some("default"),
            false,
            None,
        )
        .unwrap();
        assert!(cmd.contains("-n 'default'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_triage_command_invalid_context() {
        let result = K8sTriageCommandBuilder::build_triage_command(
            Some("kubectl"),
            None,
            false,
            Some("--bad-context"),
        );
        assert!(result.is_err());
    }

    // ============ build_crashloops_command ============

    #[test]
    fn test_build_crashloops_command_basic() {
        let cmd = K8sTriageCommandBuilder::build_crashloops_command(
            Some("kubectl"),
            None,
            false,
            50,
            None,
        )
        .unwrap();
        assert!(cmd.contains("K=\"kubectl\""), "cmd: {cmd}");
        assert!(cmd.contains("CrashLoopBackOff"), "cmd: {cmd}");
        assert!(cmd.contains("--tail=50"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_crashloops_command_invalid_tail() {
        let result = K8sTriageCommandBuilder::build_crashloops_command(
            Some("kubectl"),
            None,
            false,
            0,
            None,
        );
        assert!(result.is_err());
    }

    // ============ build_pod_health_command ============

    #[test]
    fn test_build_pod_health_command_with_label() {
        let cmd = K8sTriageCommandBuilder::build_pod_health_command(
            Some("kubectl"),
            None,
            false,
            Some("app=nginx"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("-l 'app=nginx'"), "cmd: {cmd}");
        assert!(cmd.contains("notReadyReasons"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_pod_health_command_no_label() {
        let cmd = K8sTriageCommandBuilder::build_pod_health_command(
            Some("kubectl"),
            Some("production"),
            false,
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("-n 'production'"), "cmd: {cmd}");
        assert!(!cmd.contains(" -l "), "cmd: {cmd}");
    }

    // ============ build_pending_command ============

    #[test]
    fn test_build_pending_command_basic() {
        let cmd =
            K8sTriageCommandBuilder::build_pending_command(Some("kubectl"), None, false, None)
                .unwrap();
        assert!(cmd.contains("FailedScheduling"), "cmd: {cmd}");
        assert!(cmd.contains("schedulerMessages"), "cmd: {cmd}");
    }

    // ============ build_node_status_command ============

    #[test]
    fn test_build_node_status_command_basic() {
        let cmd =
            K8sTriageCommandBuilder::build_node_status_command(Some("kubectl"), None).unwrap();
        assert!(cmd.contains("get nodes"), "cmd: {cmd}");
        assert!(cmd.contains("kubeletVersion"), "cmd: {cmd}");
        assert!(cmd.contains(".problem"), "cmd: {cmd}");
    }

    // ============ build_watch_command ============

    #[test]
    fn test_build_watch_command_pods() {
        let cmd = K8sTriageCommandBuilder::build_watch_command(
            Some("kubectl"),
            "pods",
            None,
            false,
            None,
            30,
            None,
        )
        .unwrap();
        assert!(cmd.contains("timeout 30"), "cmd: {cmd}");
        assert!(cmd.contains("--watch-only"), "cmd: {cmd}");
        assert!(cmd.contains("timeout reached"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_watch_command_invalid_resource() {
        let result = K8sTriageCommandBuilder::build_watch_command(
            Some("kubectl"),
            "secrets",
            None,
            false,
            None,
            30,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_watch_command_invalid_timeout() {
        let result = K8sTriageCommandBuilder::build_watch_command(
            Some("kubectl"),
            "pods",
            None,
            false,
            None,
            0,
            None,
        );
        assert!(result.is_err());
    }

    // ============ is_valid_binary_path ============

    #[test]
    fn test_is_valid_binary_path_empty() {
        assert!(!is_valid_binary_path(""));
    }

    #[test]
    fn test_is_valid_binary_path_valid() {
        assert!(is_valid_binary_path("kubectl"));
        assert!(is_valid_binary_path("/usr/local/bin/kubectl"));
        assert!(is_valid_binary_path("k3s"));
    }

    #[test]
    fn test_is_valid_binary_path_injection() {
        assert!(!is_valid_binary_path("kubectl; rm -rf /"));
        assert!(!is_valid_binary_path("kubectl && evil"));
    }
}
