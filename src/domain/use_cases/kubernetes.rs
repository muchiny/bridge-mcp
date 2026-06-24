//! Kubernetes Command Builder
//!
//! Builds kubectl and helm CLI commands for remote execution via SSH.
//! Supports auto-detection of kubectl binary (k8s, k3s, `microk8s`).

use std::collections::HashMap;
use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate a binary path contains only safe characters.
fn is_valid_binary_path(bin: &str) -> bool {
    !bin.is_empty()
        && bin
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

/// Generate the kubectl binary detection prefix.
///
/// If `kubectl_bin` is provided, use it directly. Otherwise, auto-detect
/// by probing for `kubectl`, `k3s kubectl`, or `microk8s kubectl`.
#[must_use]
pub fn kubectl_detect_prefix(kubectl_bin: Option<&str>) -> String {
    if let Some(bin) = kubectl_bin {
        if is_valid_binary_path(bin) {
            format!("{bin} ")
        } else {
            // Invalid binary path, fall back to auto-detection
            kubectl_detect_prefix(None)
        }
    } else {
        "$(if command -v kubectl &>/dev/null; then echo kubectl; \
         elif command -v k3s &>/dev/null; then echo 'k3s kubectl'; \
         elif command -v microk8s &>/dev/null; then echo 'microk8s kubectl'; \
         else echo 'kubectl/k3s/microk8s not installed on host' >&2; echo false; fi) "
            .to_string()
    }
}

/// Generate the helm binary detection prefix.
///
/// If `helm_bin` is provided, use it directly. Otherwise, auto-detect.
#[must_use]
pub fn helm_detect_prefix(helm_bin: Option<&str>) -> String {
    if let Some(bin) = helm_bin {
        if is_valid_binary_path(bin) {
            format!("{bin} ")
        } else {
            // Invalid binary path, fall back to auto-detection
            helm_detect_prefix(None)
        }
    } else {
        "$(if command -v helm &>/dev/null; then echo helm; \
         else echo 'helm not installed on host' >&2; echo false; fi) "
            .to_string()
    }
}

/// Generate an optional `KUBECONFIG=<path>` environment prefix.
///
/// Returns an empty string if no kubeconfig is provided or the path is invalid.
/// This is useful for K3s environments where helm needs explicit kubeconfig.
#[must_use]
pub fn kubeconfig_env_prefix(kubeconfig: Option<&str>) -> String {
    match kubeconfig {
        Some(path) if is_valid_binary_path(path) => format!("KUBECONFIG={path} "),
        _ => String::new(),
    }
}

/// Validate a kubectl context name: non-empty, not flag-like, shell-safe charset.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the context is empty, starts
/// with `-` (flag-like values such as `--kubeconfig=/etc/x`), or contains
/// characters outside `[A-Za-z0-9._@:/-]` plus space (rejecting injection
/// payloads such as `prod$(kubectl delete pods --all)`).
pub fn validate_context(context: &str) -> Result<()> {
    if context.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "context must not be empty".to_string(),
        });
    }
    if context.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("context must not look like a flag: {context}"),
        });
    }
    if !context.chars().all(|c| {
        matches!(c,
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '@' | ':' | '/' | '-' | ' ')
    }) {
        return Err(BridgeError::CommandDenied {
            reason: format!("context contains disallowed characters: {context}"),
        });
    }
    Ok(())
}

/// Validate an API server raw path for `kubectl get --raw`.
///
/// # Rules
/// - Non-empty
/// - Must start with `/`
/// - Charset: `[A-Za-z0-9._~/?=&%-]` (allows query strings with `?` and `%xx`)
/// - No `..` segments (path traversal)
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] with the offending path.
pub fn validate_raw_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: format!("raw path must not be empty: {path}"),
        });
    }
    if !path.starts_with('/') {
        return Err(BridgeError::CommandDenied {
            reason: format!("raw path must start with '/': {path}"),
        });
    }
    // Check for path traversal
    for segment in path.split('/') {
        if segment == ".." {
            return Err(BridgeError::CommandDenied {
                reason: format!("raw path contains path traversal: {path}"),
            });
        }
    }
    // Validate charset - only allow [A-Za-z0-9._~/?=&%-]
    for ch in path.chars() {
        if !matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '~' | '/' | '?' | '=' | '&' | '%' | '-')
        {
            return Err(BridgeError::CommandDenied {
                reason: format!("raw path contains disallowed character '{ch}': {path}"),
            });
        }
    }
    Ok(())
}

/// Build an optional ` --context=<ctx>` flag (leading space, shell-escaped).
///
/// Safe context names (only `[A-Za-z0-9._@:/-]`) are emitted bare; names
/// containing spaces or other special characters are single-quoted.
///
/// Returns an empty string when no context is supplied.
#[must_use]
pub fn kubectl_context_flag(context: Option<&str>) -> String {
    match context {
        Some(ctx) => {
            let needs_quoting = ctx
                .chars()
                .any(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '@' | ':' | '/' | '-'));
            if needs_quoting {
                format!(" --context={}", shell_escape(ctx))
            } else {
                format!(" --context={ctx}")
            }
        }
        None => String::new(),
    }
}

/// Builds kubectl CLI commands for remote execution.
pub struct KubernetesCommandBuilder;

impl KubernetesCommandBuilder {
    /// Build a `kubectl get` command.
    ///
    /// Constructs: `{kubectl} get {resource} [{name}] [-n {ns}] [-A]
    /// [-l {selector}] [--field-selector {fs}] [-o {output}]
    /// [--sort-by={sort}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_get_command(
        kubectl_bin: Option<&str>,
        resource: &str,
        name: Option<&str>,
        namespace: Option<&str>,
        all_namespaces: bool,
        label_selector: Option<&str>,
        field_selector: Option<&str>,
        output: Option<&str>,
        sort_by: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_resource = shell_escape(resource);
        let mut cmd = format!("{prefix}get {escaped_resource}");

        if let Some(n) = name {
            let _ = write!(cmd, " {}", shell_escape(n));
        }

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if all_namespaces {
            cmd.push_str(" -A");
        }

        if let Some(selector) = label_selector {
            let _ = write!(cmd, " -l {}", shell_escape(selector));
        }

        if let Some(fs) = field_selector {
            let _ = write!(cmd, " --field-selector {}", shell_escape(fs));
        }

        if let Some(out) = output {
            let _ = write!(cmd, " -o {}", shell_escape(out));
        }

        if let Some(sort) = sort_by {
            let _ = write!(cmd, " --sort-by={}", shell_escape(sort));
        }

        cmd
    }

    /// Build a `kubectl get events` command sorted by last timestamp.
    ///
    /// Constructs: `{kubectl} get events --sort-by=.lastTimestamp [-n {ns}]
    /// [-A] [--field-selector {fs}]`
    #[must_use]
    pub fn build_events_command(
        kubectl_bin: Option<&str>,
        namespace: Option<&str>,
        all_namespaces: bool,
        field_selector: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}get events --sort-by=.lastTimestamp");
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if all_namespaces {
            cmd.push_str(" -A");
        }
        if let Some(fs) = field_selector {
            let _ = write!(cmd, " --field-selector {}", shell_escape(fs));
        }
        cmd
    }

    /// Build a `kubectl logs` command.
    ///
    /// Constructs: `{kubectl} logs {pod} [-n {ns}] [-c {container}]
    /// [--tail={N}] [--since={dur}] [-p] [--timestamps]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_logs_command(
        kubectl_bin: Option<&str>,
        pod: &str,
        namespace: Option<&str>,
        container: Option<&str>,
        tail: Option<u64>,
        since: Option<&str>,
        previous: bool,
        timestamps: bool,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_pod = shell_escape(pod);
        let mut cmd = format!("{prefix}logs {escaped_pod}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(c) = container {
            let _ = write!(cmd, " -c {}", shell_escape(c));
        }

        if let Some(n) = tail {
            let _ = write!(cmd, " --tail={n}");
        }

        if let Some(dur) = since {
            let _ = write!(cmd, " --since={}", shell_escape(dur));
        }

        if previous {
            cmd.push_str(" -p");
        }

        if timestamps {
            cmd.push_str(" --timestamps");
        }

        cmd
    }

    /// Build a `kubectl describe` command.
    ///
    /// Constructs: `{kubectl} describe {resource} {name} [-n {ns}]`
    #[must_use]
    pub fn build_describe_command(
        kubectl_bin: Option<&str>,
        resource: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_resource = shell_escape(resource);
        let escaped_name = shell_escape(name);
        let mut cmd = format!("{prefix}describe {escaped_resource} {escaped_name}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        cmd
    }

    /// Build a `kubectl apply` command.
    ///
    /// If `manifest` starts with `/`, `./`, or `~`, it is treated as a file
    /// path: `{kubectl} apply -f {path}`. Otherwise, it is treated as
    /// inline YAML: `echo '{yaml}' | {kubectl} apply -f -`
    #[must_use]
    pub fn build_apply_command(
        kubectl_bin: Option<&str>,
        manifest: &str,
        namespace: Option<&str>,
        dry_run: Option<&str>,
        force: bool,
        server_side: bool,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let is_file =
            manifest.starts_with('/') || manifest.starts_with("./") || manifest.starts_with('~');

        let mut cmd = if is_file {
            format!("{prefix}apply -f {}", shell_escape(manifest))
        } else {
            format!("echo {} | {prefix}apply -f -", shell_escape(manifest))
        };

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(dr) = dry_run {
            let _ = write!(cmd, " --dry-run={}", shell_escape(dr));
        }

        if force {
            cmd.push_str(" --force");
        }

        if server_side {
            cmd.push_str(" --server-side");
        }

        cmd
    }

    /// Build a `kubectl diff` command (server-side dry-run preview).
    ///
    /// If `manifest` starts with `/`, `./`, or `~` it is a file path
    /// (`{kubectl} diff -f {path}`); otherwise it is inline YAML piped in
    /// (`echo '{yaml}' | {kubectl} diff -f -`).
    #[must_use]
    pub fn build_diff_command(
        kubectl_bin: Option<&str>,
        manifest: &str,
        namespace: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let is_file =
            manifest.starts_with('/') || manifest.starts_with("./") || manifest.starts_with('~');
        let mut cmd = if is_file {
            format!("{prefix}diff -f {}", shell_escape(manifest))
        } else {
            format!("echo {} | {prefix}diff -f -", shell_escape(manifest))
        };
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        cmd
    }

    /// Build a `kubectl delete` command.
    ///
    /// Constructs: `{kubectl} delete {resource} {name} [-n {ns}]
    /// [--grace-period={N}] [--force] [--dry-run={mode}]`
    #[must_use]
    pub fn build_delete_command(
        kubectl_bin: Option<&str>,
        resource: &str,
        name: &str,
        namespace: Option<&str>,
        grace_period: Option<u64>,
        force: bool,
        dry_run: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_resource = shell_escape(resource);
        let escaped_name = shell_escape(name);
        let mut cmd = format!("{prefix}delete {escaped_resource} {escaped_name}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(gp) = grace_period {
            let _ = write!(cmd, " --grace-period={gp}");
        }

        if force {
            cmd.push_str(" --force");
        }

        if let Some(dr) = dry_run {
            let _ = write!(cmd, " --dry-run={}", shell_escape(dr));
        }

        cmd
    }

    /// Build a `kubectl rollout` command.
    ///
    /// Constructs: `{kubectl} rollout {action} {resource} [-n {ns}]
    /// [--to-revision={N}]`
    #[must_use]
    pub fn build_rollout_command(
        kubectl_bin: Option<&str>,
        action: &str,
        resource: &str,
        namespace: Option<&str>,
        to_revision: Option<u64>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_action = shell_escape(action);
        let escaped_resource = shell_escape(resource);
        let mut cmd = format!("{prefix}rollout {escaped_action} {escaped_resource}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(rev) = to_revision {
            let _ = write!(cmd, " --to-revision={rev}");
        }

        cmd
    }

    /// Build a `kubectl scale` command.
    ///
    /// Constructs: `{kubectl} scale {resource} --replicas={N} [-n {ns}]`
    #[must_use]
    pub fn build_scale_command(
        kubectl_bin: Option<&str>,
        resource: &str,
        replicas: u64,
        namespace: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_resource = shell_escape(resource);
        let mut cmd = format!("{prefix}scale {escaped_resource} --replicas={replicas}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        cmd
    }

    /// Build a `kubectl exec` command.
    ///
    /// Constructs: `{kubectl} exec {pod} [-n {ns}] [-c {container}]
    /// -- {command}`
    #[must_use]
    pub fn build_exec_command(
        kubectl_bin: Option<&str>,
        pod: &str,
        command: &str,
        namespace: Option<&str>,
        container: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_pod = shell_escape(pod);
        let mut cmd = format!("{prefix}exec {escaped_pod}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(c) = container {
            let _ = write!(cmd, " -c {}", shell_escape(c));
        }

        let _ = write!(cmd, " -- sh -c {}", shell_escape(command));

        cmd
    }

    /// Build a `kubectl top` command.
    ///
    /// Constructs: `{kubectl} top {resource_type} [-n {ns}]
    /// [--sort-by={sort}] [--containers]`
    #[must_use]
    pub fn build_top_command(
        kubectl_bin: Option<&str>,
        resource_type: &str,
        namespace: Option<&str>,
        all_namespaces: bool,
        sort_by: Option<&str>,
        containers: bool,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_type = shell_escape(resource_type);
        let mut cmd = format!("{prefix}top {escaped_type}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if all_namespaces {
            cmd.push_str(" -A");
        }

        if let Some(sort) = sort_by {
            let _ = write!(cmd, " --sort-by={}", shell_escape(sort));
        }

        if containers {
            cmd.push_str(" --containers");
        }

        cmd
    }

    /// Validate a kubectl delete operation for safety.
    ///
    /// Blocks deletion of critical namespaces: `kube-system`,
    /// `kube-public`, `default`, `kube-node-lease`.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the delete targets a
    /// protected namespace.
    pub fn validate_delete(resource: &str, name: &str) -> Result<()> {
        let protected = ["kube-system", "kube-public", "default", "kube-node-lease"];

        if resource.eq_ignore_ascii_case("namespace") || resource.eq_ignore_ascii_case("ns") {
            let lower_name = name.to_lowercase();
            if protected.contains(&lower_name.as_str()) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Deletion of namespace '{name}' is blocked. \
                         Protected namespaces: {protected:?}"
                    ),
                });
            }
        }

        Ok(())
    }

    /// Validate a rollout action.
    ///
    /// Only allows: `status`, `restart`, `undo`, `history`, `pause`, `resume`.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the action is not in
    /// the allowed list.
    pub fn validate_rollout_action(action: &str) -> Result<()> {
        let allowed = ["status", "restart", "undo", "history", "pause", "resume"];
        let lower = action.to_lowercase();

        if allowed.contains(&lower.as_str()) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Rollout action '{action}' is not allowed. \
                     Allowed actions: {allowed:?}"
                ),
            })
        }
    }

    /// Validate a Kubernetes namespace name (DNS-1123 label).
    ///
    /// Rejects empty strings, names exceeding 63 chars, names containing
    /// uppercase or non `[a-z0-9-]` characters, and names that don't start
    /// or end with an alphanumeric. This catches flag-like values such as
    /// `--all-namespaces` (the literal `--all-namespaces` was previously
    /// accepted as a namespace name and silently produced empty results).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` when the value is not a valid
    /// DNS-1123 label.
    pub fn validate_namespace(ns: &str) -> Result<()> {
        if ns.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Namespace cannot be empty".to_string(),
            });
        }
        if ns.len() > 63 {
            return Err(BridgeError::CommandDenied {
                reason: format!("Namespace '{ns}' exceeds 63 chars (DNS-1123 label limit)"),
            });
        }
        let bytes = ns.as_bytes();
        let head_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
        let tail_ok =
            bytes[bytes.len() - 1].is_ascii_lowercase() || bytes[bytes.len() - 1].is_ascii_digit();
        let chars_ok = ns
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !(head_ok && tail_ok && chars_ok) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Namespace '{ns}' is not a valid DNS-1123 label \
                     (lowercase alphanumeric and hyphens only, must start and end with alphanumeric)"
                ),
            });
        }
        Ok(())
    }

    /// Build a `kubectl wait` command (block until a condition holds).
    ///
    /// Constructs: `{kubectl} wait {resource} [{name}] --for={cond}
    /// [-n {ns}] [-A] [-l {selector}] [--timeout={dur}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_wait_command(
        kubectl_bin: Option<&str>,
        resource: &str,
        name: Option<&str>,
        condition: &str,
        namespace: Option<&str>,
        all_namespaces: bool,
        label_selector: Option<&str>,
        timeout: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}wait {}", shell_escape(resource));
        if let Some(n) = name {
            let _ = write!(cmd, " {}", shell_escape(n));
        }
        let _ = write!(cmd, " --for={}", shell_escape(condition));
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if all_namespaces {
            cmd.push_str(" -A");
        }
        if let Some(sel) = label_selector {
            let _ = write!(cmd, " -l {}", shell_escape(sel));
        }
        if let Some(t) = timeout {
            let _ = write!(cmd, " --timeout={}", shell_escape(t));
        }
        cmd
    }

    /// Validate the `helm get` subcommand against the allowed set.
    ///
    /// # Errors
    /// Returns `BridgeError::CommandDenied` if `subcommand` is not one of
    /// all/values/manifest/hooks/notes.
    pub fn validate_helm_get_subcommand(subcommand: &str) -> Result<()> {
        let allowed = ["all", "values", "manifest", "hooks", "notes"];
        if allowed.contains(&subcommand) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Helm get subcommand '{subcommand}' is not allowed. Allowed: {allowed:?}"
                ),
            })
        }
    }

    /// Validate `resource_type` for the top command.
    ///
    /// Only allows: `pods`, `nodes`.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the resource type is
    /// not in the allowed list.
    pub fn validate_top_resource(resource_type: &str) -> Result<()> {
        let allowed = ["pods", "nodes"];
        let lower = resource_type.to_lowercase();

        if allowed.contains(&lower.as_str()) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Top resource type '{resource_type}' is not allowed. \
                     Allowed types: {allowed:?}"
                ),
            })
        }
    }

    /// Build a `kubectl patch <target> --type=<type> -p <patch>` command.
    ///
    /// Applies a strategic, merge, or JSON patch to a live resource.
    /// `patch_type` is one of `strategic`, `merge`, `json` (validated by the
    /// handler before this builder is called).
    #[must_use]
    pub fn build_patch_command(
        kubectl_bin: Option<&str>,
        target: &str,
        patch: &str,
        patch_type: &str,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!(
            "{prefix}patch {} --type={} -p {}",
            shell_escape(target),
            shell_escape(patch_type),
            shell_escape(patch)
        );
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        cmd.push_str(&kubectl_context_flag(context));
        cmd
    }

    /// Build a `kubectl set <subcommand> <target> <assignments...>` command.
    ///
    /// Constructs: `{kubectl} set {subcommand} {target} {assignments...}
    /// [-n {ns}] [--context={ctx}]`
    ///
    /// `subcommand` is one of `image`, `env`, `resources` (validated by the
    /// handler before this builder is called).
    #[must_use]
    pub fn build_set_command(
        kubectl_bin: Option<&str>,
        subcommand: &str,
        target: &str,
        assignments: &[String],
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!(
            "{prefix}set {} {}",
            shell_escape(subcommand),
            shell_escape(target)
        );
        for a in assignments {
            let _ = write!(cmd, " {}", shell_escape(a));
        }
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        cmd.push_str(&kubectl_context_flag(context));
        cmd
    }

    /// Build a `kubectl cordon|uncordon <node>` command.
    ///
    /// Constructs: `{kubectl} cordon|uncordon {node} [--context={ctx}]`
    ///
    /// Pass `cordon = true` to mark a node unschedulable; `false` to mark it
    /// schedulable again (`kubectl uncordon`). Both are idempotent — running
    /// the same verb twice converges to the same state.
    #[must_use]
    pub fn build_cordon_command(
        kubectl_bin: Option<&str>,
        node: &str,
        cordon: bool,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let verb = if cordon { "cordon" } else { "uncordon" };
        let mut cmd = format!("{prefix}{verb} {}", shell_escape(node));
        cmd.push_str(&kubectl_context_flag(context));
        cmd
    }

    /// Build `kubectl drain <node>` with safety flags.
    ///
    /// Constructs: `{kubectl} drain {node} [--ignore-daemonsets]
    /// [--delete-emptydir-data] [--force] [--context={ctx}]`
    ///
    /// **DESTRUCTIVE** — evicting pods from a node causes workload disruption
    /// that is not automatically reversed when the node returns.
    /// Always cordon first; use `--force` only when stuck on pods that do not
    /// have a controller (bare pods will be lost permanently).
    ///
    /// `ignore_daemonsets` defaults to `true` in the handler — `DaemonSet` pods
    /// cannot be evicted and must be skipped for the drain to proceed.
    /// `delete_emptydir` permanently deletes emptyDir volume data.
    #[must_use]
    pub fn build_drain_command(
        kubectl_bin: Option<&str>,
        node: &str,
        ignore_daemonsets: bool,
        delete_emptydir: bool,
        force: bool,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}drain {}", shell_escape(node));
        if ignore_daemonsets {
            cmd.push_str(" --ignore-daemonsets");
        }
        if delete_emptydir {
            cmd.push_str(" --delete-emptydir-data");
        }
        if force {
            cmd.push_str(" --force");
        }
        cmd.push_str(&kubectl_context_flag(context));
        cmd
    }

    /// Build a `kubectl auth can-i <verb> <resource>` command (RBAC preflight).
    ///
    /// Constructs: `{kubectl} auth can-i {verb} {resource} [-n {ns}]
    /// [--as {user}] [--context={ctx}]`
    ///
    /// Use this before a mutating change to fail fast on permission errors.
    /// Pass `as_user` to impersonate a user or service account (maps to `kubectl --as`).
    /// Use `context` for multi-cluster targeting.
    #[must_use]
    pub fn build_auth_can_i_command(
        kubectl_bin: Option<&str>,
        verb: &str,
        resource: &str,
        namespace: Option<&str>,
        as_user: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!(
            "{prefix}auth can-i {} {}",
            shell_escape(verb),
            shell_escape(resource)
        );
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if let Some(u) = as_user {
            let _ = write!(cmd, " --as {}", shell_escape(u));
        }
        cmd.push_str(&kubectl_context_flag(context));
        cmd
    }

    /// Build a `kubectl get --raw <path>` command.
    ///
    /// Constructs: `{kubectl} get --raw={path} [--context={ctx}]`
    ///
    /// Use this for direct API server access (e.g. `/readyz?verbose`,
    /// `/livez`, `/healthz`, custom endpoints). The path must be
    /// validated with [`validate_raw_path`] before calling this builder.
    #[must_use]
    pub fn build_get_raw_command(
        kubectl_bin: Option<&str>,
        path: &str,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_path = shell_escape(path);
        let context_flag = kubectl_context_flag(context);
        format!("{prefix}get --raw={escaped_path}{context_flag}")
    }

    /// Build a `kubectl cluster-info [dump]` command.
    ///
    /// Constructs: `{kubectl} cluster-info [dump] [--context={ctx}]`
    ///
    /// Without `dump`: prints control-plane and `CoreDNS` addresses.
    /// With `dump`: produces a verbose diagnostic dump (much larger output).
    #[must_use]
    pub fn build_cluster_info_command(
        kubectl_bin: Option<&str>,
        dump: bool,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let context_flag = kubectl_context_flag(context);
        if dump {
            format!("{prefix}cluster-info dump{context_flag}")
        } else {
            format!("{prefix}cluster-info{context_flag}")
        }
    }

    /// Build a `kubectl version -o json [--client]` command.
    ///
    /// Constructs: `{kubectl} version -o json [--client] [--context={ctx}]`
    ///
    /// Use `client_only = true` to skip the server version check (useful
    /// when the API server may be temporarily unavailable).
    #[must_use]
    pub fn build_version_command(
        kubectl_bin: Option<&str>,
        client_only: bool,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let context_flag = kubectl_context_flag(context);
        if client_only {
            format!("{prefix}version -o json --client{context_flag}")
        } else {
            format!("{prefix}version -o json{context_flag}")
        }
    }

    /// Build a `kubectl api-resources` command.
    ///
    /// Constructs: `{kubectl} api-resources [--namespaced={bool}]
    /// [--api-group={g}] [--verbs={v}] [-o {fmt}] [--context={ctx}]`
    #[must_use]
    pub fn build_api_resources_command(
        kubectl_bin: Option<&str>,
        namespaced: Option<bool>,
        api_group: Option<&str>,
        verbs: Option<&str>,
        output: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let context_flag = kubectl_context_flag(context);
        let mut cmd = format!("{prefix}api-resources");
        if let Some(ns) = namespaced {
            let _ = write!(cmd, " --namespaced={ns}");
        }
        if let Some(grp) = api_group {
            let _ = write!(cmd, " --api-group={}", shell_escape(grp));
        }
        if let Some(v) = verbs {
            let _ = write!(cmd, " --verbs={}", shell_escape(v));
        }
        if let Some(o) = output {
            let _ = write!(cmd, " -o {}", shell_escape(o));
        }
        cmd.push_str(&context_flag);
        cmd
    }

    /// Build a `kubectl api-versions` command.
    ///
    /// Constructs: `{kubectl} api-versions [--context={ctx}]`
    #[must_use]
    pub fn build_api_versions_command(kubectl_bin: Option<&str>, context: Option<&str>) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let context_flag = kubectl_context_flag(context);
        format!("{prefix}api-versions{context_flag}")
    }

    /// Build a `kubectl get nodes` command that emits per-node condition rows.
    ///
    /// Constructs a compound command that pipes `kubectl get nodes -o json`
    /// through `jq` to produce a JSON array of objects with `name` and
    /// `conditions` (object keyed by condition type, value = Status string).
    ///
    /// Requires `jq` on the remote host; exits with code 3 when missing.
    /// Use an optional `node` name to scope to a single node.
    #[must_use]
    pub fn build_node_conditions_command(
        kubectl_bin: Option<&str>,
        node: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let p = prefix.trim_end();
        let context_flag = kubectl_context_flag(context);
        let node_arg = if let Some(n) = node {
            format!(" {}", shell_escape(n))
        } else {
            String::new()
        };
        format!(
            "command -v jq >/dev/null 2>&1 || \
             {{ echo 'jq not installed on host (required for node conditions rollup)' >&2; exit 3; }}; \
             P={p}; $P get nodes{node_arg} -o json{context_flag} | \
             jq '[.items[] | {{name: .metadata.name, conditions: (.status.conditions | \
             map({{(.type): .status}}) | add)}}]'"
        )
    }

    /// Build a compound command that prints allocatable capacity per node and
    /// summarises running container CPU requests.
    ///
    /// Uses `jq` on the remote host; returns a JSON array of objects with
    /// `node`, `allocatable` (cpu/memory/pods), and `requested` (count of
    /// running containers with CPU requests).
    ///
    /// Requires `jq` on the remote host; exits with code 3 when missing.
    #[must_use]
    pub fn build_node_capacity_command(
        kubectl_bin: Option<&str>,
        node: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let p = prefix.trim_end();
        let context_flag = kubectl_context_flag(context);
        let node_arg = if let Some(n) = node {
            format!(" {}", shell_escape(n))
        } else {
            String::new()
        };
        format!(
            "command -v jq >/dev/null 2>&1 || \
             {{ echo 'jq not installed on host (required for node capacity rollup)' >&2; exit 3; }}; \
             P={p}; NODES=$($P get nodes{node_arg} -o json{context_flag}); \
             PODS=$($P get pods -A --field-selector=status.phase=Running -o json{context_flag}); \
             echo \"$NODES\" | jq --argjson pods \"$PODS\" \
             '[.items[] | {{node: .metadata.name, \
             allocatable: {{cpu: .status.allocatable.cpu, \
             memory: .status.allocatable.memory, \
             pods: .status.allocatable.pods}}, \
             requested: ($pods.items | map(.spec.containers[].resources.requests.cpu // empty) | length)}}]'"
        )
    }

    /// Build a compound command that checks whether the metrics-server is
    /// available and functioning.
    ///
    /// Checks three things in sequence:
    /// 1. `APIService v1beta1.metrics.k8s.io` availability condition
    /// 2. `metrics-server` Deployment ready replica count
    /// 3. `kubectl top nodes` smoke test (first 3 lines)
    #[must_use]
    pub fn build_metrics_server_check_command(
        kubectl_bin: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let p = prefix.trim_end();
        let context_flag = kubectl_context_flag(context);
        format!(
            "P={p}; echo '== APIService =='; $P get apiservice v1beta1.metrics.k8s.io -o jsonpath='{{.status.conditions[?(@.type==\"Available\")].status}}'{context_flag} 2>&1; echo; echo '== Deployment =='; $P get deploy -n kube-system metrics-server -o jsonpath='{{.status.readyReplicas}}/{{.status.replicas}}'{context_flag} 2>&1; echo; echo '== top smoke =='; $P top nodes{context_flag} 2>&1 | head -3"
        )
    }
}

/// Builds helm CLI commands for remote execution.
pub struct HelmCommandBuilder;

impl HelmCommandBuilder {
    /// Build a `helm list` command.
    ///
    /// Constructs: `{helm} list [-n {ns}] [-A] [-a] [--filter {f}]
    /// [-o {output}]`
    #[must_use]
    pub fn build_list_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        namespace: Option<&str>,
        all_namespaces: bool,
        all: bool,
        filter: Option<&str>,
        output: Option<&str>,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!("{kube_env}{prefix}list");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if all_namespaces {
            cmd.push_str(" -A");
        }

        if all {
            cmd.push_str(" -a");
        }

        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }

        if let Some(out) = output {
            let _ = write!(cmd, " -o {}", shell_escape(out));
        }

        cmd
    }

    /// Build a `helm status` command.
    ///
    /// Constructs: `{helm} status {release} [-n {ns}] [-o {output}]
    /// [--revision {N}]`
    #[must_use]
    pub fn build_status_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        namespace: Option<&str>,
        output: Option<&str>,
        revision: Option<u64>,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let escaped_release = shell_escape(release);
        let mut cmd = format!("{kube_env}{prefix}status {escaped_release}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(out) = output {
            let _ = write!(cmd, " -o {}", shell_escape(out));
        }

        if let Some(rev) = revision {
            let _ = write!(cmd, " --revision {rev}");
        }

        cmd
    }

    /// Build a `helm get` command (read-only inspection of a release).
    ///
    /// `subcommand` is validated by the caller
    /// (`KubernetesCommandBuilder::validate_helm_get_subcommand`).
    ///
    /// Constructs: `[KUBECONFIG=…] {helm} get {subcommand} {release}
    /// [-n {ns}] [--revision {N}]`
    #[must_use]
    pub fn build_get_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        subcommand: &str,
        release: &str,
        namespace: Option<&str>,
        revision: Option<u64>,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let escaped_sub = shell_escape(subcommand);
        let escaped_release = shell_escape(release);
        let mut cmd = format!("{kube_env}{prefix}get {escaped_sub} {escaped_release}");
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if let Some(rev) = revision {
            let _ = write!(cmd, " --revision {rev}");
        }
        cmd
    }

    /// Build a `helm upgrade` command.
    ///
    /// Constructs: `{helm} upgrade {release} {chart} [-n {ns}]
    /// [--set k=v ...] [-f values.yaml ...] [--dry-run={mode}]
    /// [--wait] [--timeout {t}] [--install] [--version {v}]
    /// [--create-namespace]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_upgrade_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        chart: &str,
        namespace: Option<&str>,
        set_values: Option<&HashMap<String, String>>,
        values_files: Option<&[String]>,
        dry_run: Option<&str>,
        wait: bool,
        timeout: Option<&str>,
        install: bool,
        version: Option<&str>,
        create_namespace: bool,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let escaped_release = shell_escape(release);
        let escaped_chart = shell_escape(chart);
        let mut cmd = format!("{kube_env}{prefix}upgrade {escaped_release} {escaped_chart}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(vals) = set_values {
            let mut keys: Vec<&String> = vals.keys().collect();
            keys.sort();
            for key in keys {
                let val = &vals[key];
                let _ = write!(cmd, " --set {}={}", shell_escape(key), shell_escape(val));
            }
        }

        if let Some(files) = values_files {
            for file in files {
                let _ = write!(cmd, " -f {}", shell_escape(file));
            }
        }

        if let Some(dr) = dry_run {
            let _ = write!(cmd, " --dry-run={}", shell_escape(dr));
        }

        if wait {
            cmd.push_str(" --wait");
        }

        if let Some(t) = timeout {
            let _ = write!(cmd, " --timeout {}", shell_escape(t));
        }

        if install {
            cmd.push_str(" --install");
        }

        if let Some(v) = version {
            let _ = write!(cmd, " --version {}", shell_escape(v));
        }

        if create_namespace {
            cmd.push_str(" --create-namespace");
        }

        cmd
    }

    /// Build a `helm install` command.
    ///
    /// Constructs: `{helm} install {release} {chart} [-n {ns}]
    /// [--set k=v ...] [-f values.yaml ...] [--dry-run={mode}]
    /// [--wait] [--create-namespace] [--version {v}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_install_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        chart: &str,
        namespace: Option<&str>,
        set_values: Option<&HashMap<String, String>>,
        values_files: Option<&[String]>,
        dry_run: Option<&str>,
        wait: bool,
        create_namespace: bool,
        version: Option<&str>,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let escaped_release = shell_escape(release);
        let escaped_chart = shell_escape(chart);
        let mut cmd = format!("{kube_env}{prefix}install {escaped_release} {escaped_chart}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(vals) = set_values {
            let mut keys: Vec<&String> = vals.keys().collect();
            keys.sort();
            for key in keys {
                let val = &vals[key];
                let _ = write!(cmd, " --set {}={}", shell_escape(key), shell_escape(val));
            }
        }

        if let Some(files) = values_files {
            for file in files {
                let _ = write!(cmd, " -f {}", shell_escape(file));
            }
        }

        if let Some(dr) = dry_run {
            let _ = write!(cmd, " --dry-run={}", shell_escape(dr));
        }

        if wait {
            cmd.push_str(" --wait");
        }

        if create_namespace {
            cmd.push_str(" --create-namespace");
        }

        if let Some(v) = version {
            let _ = write!(cmd, " --version {}", shell_escape(v));
        }

        cmd
    }

    /// Build a `helm rollback` command.
    ///
    /// Constructs: `{helm} rollback {release} [{revision}] [-n {ns}]
    /// [--dry-run={mode}] [--wait]`
    #[must_use]
    pub fn build_rollback_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        revision: Option<u64>,
        namespace: Option<&str>,
        dry_run: Option<&str>,
        wait: bool,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let escaped_release = shell_escape(release);
        let mut cmd = format!("{kube_env}{prefix}rollback {escaped_release}");

        if let Some(rev) = revision {
            let _ = write!(cmd, " {rev}");
        }

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(dr) = dry_run {
            let _ = write!(cmd, " --dry-run={}", shell_escape(dr));
        }

        if wait {
            cmd.push_str(" --wait");
        }

        cmd
    }

    /// Build a `helm history` command.
    ///
    /// Constructs: `{helm} history {release} [-n {ns}] [-o {output}]`
    #[must_use]
    pub fn build_history_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        namespace: Option<&str>,
        output: Option<&str>,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let escaped_release = shell_escape(release);
        let mut cmd = format!("{kube_env}{prefix}history {escaped_release}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(out) = output {
            let _ = write!(cmd, " -o {}", shell_escape(out));
        }

        cmd
    }

    /// Build a `helm uninstall` command.
    ///
    /// Constructs: `{helm} uninstall {release} [-n {ns}] [--dry-run]
    /// [--keep-history]`
    #[must_use]
    pub fn build_uninstall_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        namespace: Option<&str>,
        dry_run: bool,
        keep_history: bool,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let escaped_release = shell_escape(release);
        let mut cmd = format!("{kube_env}{prefix}uninstall {escaped_release}");

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if dry_run {
            cmd.push_str(" --dry-run");
        }

        if keep_history {
            cmd.push_str(" --keep-history");
        }

        cmd
    }

    /// Build a `helm template` command (client-side render, read-only).
    ///
    /// Constructs: `[KUBECONFIG=…] {helm} template {release} {chart}
    /// [-n {ns}] [--set k=v …] [-f values.yaml …] [--version {v}]
    /// [--show-only {tpl} …]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_template_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        chart: &str,
        namespace: Option<&str>,
        set_values: Option<&HashMap<String, String>>,
        values_files: Option<&[String]>,
        version: Option<&str>,
        show_only: Option<&[String]>,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let escaped_release = shell_escape(release);
        let escaped_chart = shell_escape(chart);
        let mut cmd = format!("{kube_env}{prefix}template {escaped_release} {escaped_chart}");
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if let Some(vals) = set_values {
            let mut keys: Vec<&String> = vals.keys().collect();
            keys.sort();
            for key in keys {
                let val = &vals[key];
                let _ = write!(cmd, " --set {}={}", shell_escape(key), shell_escape(val));
            }
        }
        if let Some(files) = values_files {
            for file in files {
                let _ = write!(cmd, " -f {}", shell_escape(file));
            }
        }
        if let Some(v) = version {
            let _ = write!(cmd, " --version {}", shell_escape(v));
        }
        if let Some(only) = show_only {
            for tpl in only {
                let _ = write!(cmd, " --show-only {}", shell_escape(tpl));
            }
        }
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== shell_escape Tests ==============

    #[test]
    fn test_shell_escape_simple() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn test_shell_escape_with_single_quotes() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_with_spaces() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
    }

    #[test]
    fn test_shell_escape_with_special_chars() {
        assert_eq!(shell_escape("a&b|c;d"), "'a&b|c;d'");
    }

    #[test]
    fn test_shell_escape_empty_string() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn test_shell_escape_multiple_single_quotes() {
        assert_eq!(shell_escape("it''s"), "'it'\\'''\\''s'");
    }

    // ============== kubectl_detect_prefix Tests ==============

    #[test]
    fn test_kubectl_detect_prefix_with_bin() {
        let prefix = kubectl_detect_prefix(Some("kubectl"));
        assert_eq!(prefix, "kubectl ");
    }

    #[test]
    fn test_kubectl_detect_prefix_with_custom_bin() {
        let prefix = kubectl_detect_prefix(Some("/usr/local/bin/kubectl"));
        assert_eq!(prefix, "/usr/local/bin/kubectl ");
    }

    #[test]
    fn test_kubectl_detect_prefix_auto() {
        let prefix = kubectl_detect_prefix(None);
        assert!(prefix.contains("command -v kubectl"));
        assert!(prefix.contains("k3s kubectl"));
        assert!(prefix.contains("microk8s kubectl"));
        assert!(prefix.contains("not installed on host"));
        assert!(prefix.contains("echo false"));
    }

    // ============== helm_detect_prefix Tests ==============

    #[test]
    fn test_helm_detect_prefix_with_bin() {
        let prefix = helm_detect_prefix(Some("helm"));
        assert_eq!(prefix, "helm ");
    }

    #[test]
    fn test_helm_detect_prefix_auto() {
        let prefix = helm_detect_prefix(None);
        assert!(prefix.contains("command -v helm"));
        assert!(prefix.contains("not installed on host"));
        assert!(prefix.contains("echo false"));
    }

    // ============== build_get_command Tests ==============

    #[test]
    fn test_build_get_command_all_options() {
        let cmd = KubernetesCommandBuilder::build_get_command(
            Some("kubectl"),
            "pods",
            Some("nginx"),
            Some("default"),
            false,
            Some("app=nginx"),
            Some("status.phase=Running"),
            Some("json"),
            Some(".metadata.name"),
        );
        assert!(cmd.starts_with("kubectl get 'pods'"));
        assert!(cmd.contains("'nginx'"));
        assert!(cmd.contains("-n 'default'"));
        assert!(cmd.contains("-l 'app=nginx'"));
        assert!(cmd.contains("--field-selector 'status.phase=Running'"));
        assert!(cmd.contains("-o 'json'"));
        assert!(cmd.contains("--sort-by='.metadata.name'"));
    }

    #[test]
    fn test_build_get_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_get_command(
            Some("kubectl"),
            "pods",
            None,
            None,
            false,
            None,
            None,
            None,
            None,
        );
        assert_eq!(cmd, "kubectl get 'pods'");
    }

    #[test]
    fn test_build_get_command_all_namespaces() {
        let cmd = KubernetesCommandBuilder::build_get_command(
            Some("kubectl"),
            "services",
            None,
            None,
            true,
            None,
            None,
            None,
            None,
        );
        assert!(cmd.contains(" -A"));
    }

    #[test]
    fn test_build_get_command_auto_detect() {
        let cmd = KubernetesCommandBuilder::build_get_command(
            None, "pods", None, None, false, None, None, None, None,
        );
        assert!(cmd.contains("command -v kubectl"));
        assert!(cmd.contains("get 'pods'"));
    }

    #[test]
    fn test_build_get_command_special_chars_in_selector() {
        let cmd = KubernetesCommandBuilder::build_get_command(
            Some("kubectl"),
            "pods",
            None,
            None,
            false,
            Some("app in (web,api)"),
            None,
            None,
            None,
        );
        assert!(cmd.contains("-l 'app in (web,api)'"));
    }

    // ============== build_events_command Tests ==============

    #[test]
    fn test_build_events_command_with_namespace_and_field_selector() {
        let cmd = KubernetesCommandBuilder::build_events_command(
            Some("kubectl"),
            Some("default"),
            false,
            Some("involvedObject.name=p"),
        );
        assert!(cmd.contains("get events --sort-by=.lastTimestamp"));
        assert!(cmd.contains("-n 'default'"));
        assert!(cmd.contains("--field-selector 'involvedObject.name=p'"));
    }

    #[test]
    fn test_build_events_command_all_namespaces() {
        let cmd = KubernetesCommandBuilder::build_events_command(Some("kubectl"), None, true, None);
        assert!(cmd.contains("get events --sort-by=.lastTimestamp"));
        assert!(cmd.contains("-A"));
        assert!(!cmd.contains("-n "));
    }

    #[test]
    fn test_build_events_command_minimal() {
        let cmd =
            KubernetesCommandBuilder::build_events_command(Some("kubectl"), None, false, None);
        assert_eq!(cmd, "kubectl get events --sort-by=.lastTimestamp");
    }

    // ============== build_logs_command Tests ==============

    #[test]
    fn test_build_logs_command_all_options() {
        let cmd = KubernetesCommandBuilder::build_logs_command(
            Some("kubectl"),
            "nginx-pod",
            Some("kube-system"),
            Some("nginx"),
            Some(100),
            Some("1h"),
            true,
            true,
        );
        assert!(cmd.starts_with("kubectl logs 'nginx-pod'"));
        assert!(cmd.contains("-n 'kube-system'"));
        assert!(cmd.contains("-c 'nginx'"));
        assert!(cmd.contains("--tail=100"));
        assert!(cmd.contains("--since='1h'"));
        assert!(cmd.contains(" -p"));
        assert!(cmd.contains("--timestamps"));
    }

    #[test]
    fn test_build_logs_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_logs_command(
            Some("kubectl"),
            "my-pod",
            None,
            None,
            None,
            None,
            false,
            false,
        );
        assert_eq!(cmd, "kubectl logs 'my-pod'");
    }

    #[test]
    fn test_build_logs_command_previous_only() {
        let cmd = KubernetesCommandBuilder::build_logs_command(
            Some("kubectl"),
            "my-pod",
            None,
            None,
            None,
            None,
            true,
            false,
        );
        assert!(cmd.contains(" -p"));
        assert!(!cmd.contains("--timestamps"));
    }

    #[test]
    fn test_build_logs_command_timestamps_only() {
        let cmd = KubernetesCommandBuilder::build_logs_command(
            Some("kubectl"),
            "my-pod",
            None,
            None,
            None,
            None,
            false,
            true,
        );
        assert!(!cmd.contains(" -p"));
        assert!(cmd.contains("--timestamps"));
    }

    // ============== build_describe_command Tests ==============

    #[test]
    fn test_build_describe_command_with_namespace() {
        let cmd = KubernetesCommandBuilder::build_describe_command(
            Some("kubectl"),
            "pod",
            "nginx-abc123",
            Some("production"),
        );
        assert!(cmd.starts_with("kubectl describe 'pod' 'nginx-abc123'"));
        assert!(cmd.contains("-n 'production'"));
    }

    #[test]
    fn test_build_describe_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_describe_command(
            Some("kubectl"),
            "node",
            "worker-1",
            None,
        );
        assert_eq!(cmd, "kubectl describe 'node' 'worker-1'");
    }

    #[test]
    fn test_build_describe_command_special_chars() {
        let cmd = KubernetesCommandBuilder::build_describe_command(
            Some("kubectl"),
            "pod",
            "my-pod's-name",
            None,
        );
        assert!(cmd.contains("'my-pod'\\''s-name'"));
    }

    // ============== build_apply_command Tests ==============

    #[test]
    fn test_build_apply_command_file_path() {
        let cmd = KubernetesCommandBuilder::build_apply_command(
            Some("kubectl"),
            "/tmp/manifest.yaml",
            Some("default"),
            None,
            false,
            false,
        );
        assert!(cmd.starts_with("kubectl apply -f '/tmp/manifest.yaml'"));
        assert!(cmd.contains("-n 'default'"));
    }

    #[test]
    fn test_build_apply_command_relative_path() {
        let cmd = KubernetesCommandBuilder::build_apply_command(
            Some("kubectl"),
            "./manifests/deployment.yaml",
            None,
            None,
            false,
            false,
        );
        assert!(cmd.contains("kubectl apply -f './manifests/deployment.yaml'"));
    }

    #[test]
    fn test_build_apply_command_home_path() {
        let cmd = KubernetesCommandBuilder::build_apply_command(
            Some("kubectl"),
            "~/k8s/manifest.yaml",
            None,
            None,
            false,
            false,
        );
        assert!(cmd.contains("kubectl apply -f '~/k8s/manifest.yaml'"));
    }

    #[test]
    fn test_build_apply_command_inline_yaml() {
        let yaml = "apiVersion: v1\nkind: Pod";
        let cmd = KubernetesCommandBuilder::build_apply_command(
            Some("kubectl"),
            yaml,
            None,
            None,
            false,
            false,
        );
        assert!(cmd.starts_with("echo "));
        assert!(cmd.contains("| kubectl apply -f -"));
    }

    #[test]
    fn test_build_apply_command_dry_run() {
        let cmd = KubernetesCommandBuilder::build_apply_command(
            Some("kubectl"),
            "/tmp/manifest.yaml",
            None,
            Some("client"),
            false,
            false,
        );
        assert!(cmd.contains("--dry-run='client'"));
    }

    #[test]
    fn test_build_apply_command_force_and_server_side() {
        let cmd = KubernetesCommandBuilder::build_apply_command(
            Some("kubectl"),
            "/tmp/manifest.yaml",
            None,
            None,
            true,
            true,
        );
        assert!(cmd.contains("--force"));
        assert!(cmd.contains("--server-side"));
    }

    #[test]
    fn test_build_apply_command_all_options() {
        let cmd = KubernetesCommandBuilder::build_apply_command(
            Some("kubectl"),
            "/tmp/manifest.yaml",
            Some("staging"),
            Some("server"),
            true,
            true,
        );
        assert!(cmd.contains("-f '/tmp/manifest.yaml'"));
        assert!(cmd.contains("-n 'staging'"));
        assert!(cmd.contains("--dry-run='server'"));
        assert!(cmd.contains("--force"));
        assert!(cmd.contains("--server-side"));
    }

    // ============== build_diff_command Tests ==============

    #[test]
    fn test_build_diff_command_file_path() {
        let cmd = KubernetesCommandBuilder::build_diff_command(
            Some("kubectl"),
            "/tmp/d.yaml",
            Some("default"),
        );
        assert!(cmd.contains("diff -f '/tmp/d.yaml'"), "cmd: {cmd}");
        assert!(cmd.contains("-n 'default'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_diff_command_inline_yaml() {
        let yaml = "apiVersion: v1\nkind: Pod";
        let cmd = KubernetesCommandBuilder::build_diff_command(Some("kubectl"), yaml, None);
        assert!(cmd.contains("echo "), "cmd: {cmd}");
        assert!(cmd.contains("| "), "cmd: {cmd}");
        assert!(cmd.contains("diff -f -"), "cmd: {cmd}");
    }

    // ============== build_delete_command Tests ==============

    #[test]
    fn test_build_delete_command_all_options() {
        let cmd = KubernetesCommandBuilder::build_delete_command(
            Some("kubectl"),
            "pod",
            "nginx",
            Some("default"),
            Some(0),
            true,
            Some("client"),
        );
        assert!(cmd.starts_with("kubectl delete 'pod' 'nginx'"));
        assert!(cmd.contains("-n 'default'"));
        assert!(cmd.contains("--grace-period=0"));
        assert!(cmd.contains("--force"));
        assert!(cmd.contains("--dry-run='client'"));
    }

    #[test]
    fn test_build_delete_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_delete_command(
            Some("kubectl"),
            "pod",
            "nginx",
            None,
            None,
            false,
            None,
        );
        assert_eq!(cmd, "kubectl delete 'pod' 'nginx'");
    }

    #[test]
    fn test_build_delete_command_grace_period() {
        let cmd = KubernetesCommandBuilder::build_delete_command(
            Some("kubectl"),
            "pod",
            "nginx",
            None,
            Some(30),
            false,
            None,
        );
        assert!(cmd.contains("--grace-period=30"));
    }

    // ============== build_rollout_command Tests ==============

    #[test]
    fn test_build_rollout_command_restart() {
        let cmd = KubernetesCommandBuilder::build_rollout_command(
            Some("kubectl"),
            "restart",
            "deployment/nginx",
            Some("production"),
            None,
        );
        assert!(cmd.contains("kubectl rollout 'restart' 'deployment/nginx'"));
        assert!(cmd.contains("-n 'production'"));
    }

    #[test]
    fn test_build_rollout_command_undo_with_revision() {
        let cmd = KubernetesCommandBuilder::build_rollout_command(
            Some("kubectl"),
            "undo",
            "deployment/nginx",
            None,
            Some(3),
        );
        assert!(cmd.contains("'undo'"));
        assert!(cmd.contains("--to-revision=3"));
    }

    #[test]
    fn test_build_rollout_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_rollout_command(
            Some("kubectl"),
            "status",
            "deployment/web",
            None,
            None,
        );
        assert_eq!(cmd, "kubectl rollout 'status' 'deployment/web'");
    }

    // ============== build_scale_command Tests ==============

    #[test]
    fn test_build_scale_command_with_namespace() {
        let cmd = KubernetesCommandBuilder::build_scale_command(
            Some("kubectl"),
            "deployment/nginx",
            3,
            Some("production"),
        );
        assert!(cmd.contains("kubectl scale 'deployment/nginx' --replicas=3"));
        assert!(cmd.contains("-n 'production'"));
    }

    #[test]
    fn test_build_scale_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_scale_command(
            Some("kubectl"),
            "deployment/web",
            5,
            None,
        );
        assert_eq!(cmd, "kubectl scale 'deployment/web' --replicas=5");
    }

    #[test]
    fn test_build_scale_command_zero_replicas() {
        let cmd = KubernetesCommandBuilder::build_scale_command(
            Some("kubectl"),
            "deployment/web",
            0,
            None,
        );
        assert!(cmd.contains("--replicas=0"));
    }

    // ============== build_exec_command Tests ==============

    #[test]
    fn test_build_exec_command_all_options() {
        let cmd = KubernetesCommandBuilder::build_exec_command(
            Some("kubectl"),
            "nginx-pod",
            "ls -la /tmp",
            Some("default"),
            Some("nginx"),
        );
        assert!(cmd.starts_with("kubectl exec 'nginx-pod'"));
        assert!(cmd.contains("-n 'default'"));
        assert!(cmd.contains("-c 'nginx'"));
        assert!(cmd.contains("-- sh -c 'ls -la /tmp'"));
    }

    #[test]
    fn test_build_exec_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_exec_command(
            Some("kubectl"),
            "my-pod",
            "whoami",
            None,
            None,
        );
        assert_eq!(cmd, "kubectl exec 'my-pod' -- sh -c 'whoami'");
    }

    #[test]
    fn test_build_exec_command_with_namespace_only() {
        let cmd = KubernetesCommandBuilder::build_exec_command(
            Some("kubectl"),
            "my-pod",
            "date",
            Some("kube-system"),
            None,
        );
        assert!(cmd.contains("-n 'kube-system'"));
        // No container flag (-c before --), only sh -c after --
        let before_separator = cmd.split(" -- ").next().unwrap_or("");
        assert!(!before_separator.contains("-c "));
        assert!(cmd.contains("-- sh -c 'date'"));
    }

    // ============== build_top_command Tests ==============

    #[test]
    fn test_build_top_command_pods_all_options() {
        let cmd = KubernetesCommandBuilder::build_top_command(
            Some("kubectl"),
            "pods",
            Some("default"),
            false,
            Some("cpu"),
            true,
        );
        assert!(cmd.starts_with("kubectl top 'pods'"));
        assert!(cmd.contains("-n 'default'"));
        assert!(cmd.contains("--sort-by='cpu'"));
        assert!(cmd.contains("--containers"));
    }

    #[test]
    fn test_build_top_command_nodes_minimal() {
        let cmd = KubernetesCommandBuilder::build_top_command(
            Some("kubectl"),
            "nodes",
            None,
            false,
            None,
            false,
        );
        assert_eq!(cmd, "kubectl top 'nodes'");
    }

    #[test]
    fn test_build_top_command_no_containers() {
        let cmd = KubernetesCommandBuilder::build_top_command(
            Some("kubectl"),
            "pods",
            None,
            false,
            None,
            false,
        );
        assert!(!cmd.contains("--containers"));
    }

    #[test]
    fn test_build_top_command_all_namespaces() {
        let cmd = KubernetesCommandBuilder::build_top_command(
            Some("kubectl"),
            "pods",
            None,
            true,
            None,
            false,
        );
        assert_eq!(cmd, "kubectl top 'pods' -A");
    }

    // ============== validate_delete Tests ==============

    #[test]
    fn test_validate_namespace_accepts_valid_dns1123_labels() {
        for ns in [
            "default",
            "kube-system",
            "argocd",
            "media-stack",
            "ns-1",
            "a",
            "z9",
        ] {
            assert!(
                KubernetesCommandBuilder::validate_namespace(ns).is_ok(),
                "expected {ns:?} to validate"
            );
        }
    }

    #[test]
    fn test_validate_namespace_rejects_flag_like_values() {
        // The original bug: passing namespace=--all-namespaces was accepted as
        // a literal namespace name. kubectl then ran -n '--all-namespaces' and
        // returned "No resources found in --all-namespaces namespace".
        let err = KubernetesCommandBuilder::validate_namespace("--all-namespaces").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Namespace"), "unexpected reason: {reason}");
            }
            other => panic!("expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_namespace_rejects_empty_and_invalid_chars() {
        for bad in [
            "",
            "-leading-dash",
            "trailing-dash-",
            "UPPER",
            "with space",
            "with_underscore",
            "with.dot",
            "shell$inject",
        ] {
            assert!(
                KubernetesCommandBuilder::validate_namespace(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_validate_namespace_rejects_oversized() {
        let too_long = "a".repeat(64);
        assert!(KubernetesCommandBuilder::validate_namespace(&too_long).is_err());
    }

    #[test]
    fn test_validate_delete_kube_system() {
        let result = KubernetesCommandBuilder::validate_delete("namespace", "kube-system");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("kube-system"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_delete_kube_public() {
        let result = KubernetesCommandBuilder::validate_delete("namespace", "kube-public");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_delete_default() {
        let result = KubernetesCommandBuilder::validate_delete("namespace", "default");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_delete_kube_node_lease() {
        let result = KubernetesCommandBuilder::validate_delete("namespace", "kube-node-lease");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_delete_ns_shorthand() {
        let result = KubernetesCommandBuilder::validate_delete("ns", "kube-system");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_delete_case_insensitive_resource() {
        let result = KubernetesCommandBuilder::validate_delete("Namespace", "kube-system");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_delete_case_insensitive_name() {
        let result = KubernetesCommandBuilder::validate_delete("namespace", "KUBE-SYSTEM");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_delete_custom_namespace_allowed() {
        let result = KubernetesCommandBuilder::validate_delete("namespace", "my-namespace");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_delete_non_namespace_resource_allowed() {
        let result = KubernetesCommandBuilder::validate_delete("pod", "kube-system");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_delete_deployment_allowed() {
        let result = KubernetesCommandBuilder::validate_delete("deployment", "nginx");
        assert!(result.is_ok());
    }

    // ============== validate_rollout_action Tests ==============

    #[test]
    fn test_validate_rollout_action_status() {
        assert!(KubernetesCommandBuilder::validate_rollout_action("status").is_ok());
    }

    #[test]
    fn test_validate_rollout_action_restart() {
        assert!(KubernetesCommandBuilder::validate_rollout_action("restart").is_ok());
    }

    #[test]
    fn test_validate_rollout_action_undo() {
        assert!(KubernetesCommandBuilder::validate_rollout_action("undo").is_ok());
    }

    #[test]
    fn test_validate_rollout_action_history() {
        assert!(KubernetesCommandBuilder::validate_rollout_action("history").is_ok());
    }

    #[test]
    fn test_validate_rollout_action_case_insensitive() {
        assert!(KubernetesCommandBuilder::validate_rollout_action("Status").is_ok());
        assert!(KubernetesCommandBuilder::validate_rollout_action("RESTART").is_ok());
    }

    #[test]
    fn test_validate_rollout_allows_pause_resume() {
        assert!(KubernetesCommandBuilder::validate_rollout_action("pause").is_ok());
        assert!(KubernetesCommandBuilder::validate_rollout_action("resume").is_ok());
        assert!(KubernetesCommandBuilder::validate_rollout_action("status").is_ok());
        assert!(KubernetesCommandBuilder::validate_rollout_action("bogus").is_err());
    }

    #[test]
    fn test_validate_rollout_action_invalid_denied() {
        assert!(KubernetesCommandBuilder::validate_rollout_action("invalid").is_err());
    }

    // ============== validate_top_resource Tests ==============

    #[test]
    fn test_validate_top_resource_pods() {
        assert!(KubernetesCommandBuilder::validate_top_resource("pods").is_ok());
    }

    #[test]
    fn test_validate_top_resource_nodes() {
        assert!(KubernetesCommandBuilder::validate_top_resource("nodes").is_ok());
    }

    #[test]
    fn test_validate_top_resource_case_insensitive() {
        assert!(KubernetesCommandBuilder::validate_top_resource("Pods").is_ok());
        assert!(KubernetesCommandBuilder::validate_top_resource("NODES").is_ok());
    }

    #[test]
    fn test_validate_top_resource_services_denied() {
        let result = KubernetesCommandBuilder::validate_top_resource("services");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("services"));
                assert!(reason.contains("not allowed"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_top_resource_deployments_denied() {
        assert!(KubernetesCommandBuilder::validate_top_resource("deployments").is_err());
    }

    // ============== HelmCommandBuilder: build_list_command Tests ======

    #[test]
    fn test_helm_build_list_all_options() {
        let cmd = HelmCommandBuilder::build_list_command(
            Some("helm"),
            None,
            Some("production"),
            true,
            true,
            Some("nginx"),
            Some("json"),
        );
        assert!(cmd.starts_with("helm list"));
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains(" -A"));
        assert!(cmd.contains(" -a"));
        assert!(cmd.contains("--filter 'nginx'"));
        assert!(cmd.contains("-o 'json'"));
    }

    #[test]
    fn test_helm_build_list_minimal() {
        let cmd = HelmCommandBuilder::build_list_command(
            Some("helm"),
            None,
            None,
            false,
            false,
            None,
            None,
        );
        assert_eq!(cmd, "helm list");
    }

    #[test]
    fn test_helm_build_list_auto_detect() {
        let cmd =
            HelmCommandBuilder::build_list_command(None, None, None, false, false, None, None);
        assert!(cmd.contains("command -v helm"));
        assert!(cmd.contains("list"));
    }

    // ============== HelmCommandBuilder: build_status_command Tests ====

    #[test]
    fn test_helm_build_status_all_options() {
        let cmd = HelmCommandBuilder::build_status_command(
            Some("helm"),
            None,
            "my-release",
            Some("staging"),
            Some("json"),
            Some(5),
        );
        assert!(cmd.starts_with("helm status 'my-release'"));
        assert!(cmd.contains("-n 'staging'"));
        assert!(cmd.contains("-o 'json'"));
        assert!(cmd.contains("--revision 5"));
    }

    #[test]
    fn test_helm_build_status_minimal() {
        let cmd = HelmCommandBuilder::build_status_command(
            Some("helm"),
            None,
            "my-release",
            None,
            None,
            None,
        );
        assert_eq!(cmd, "helm status 'my-release'");
    }

    // ============== HelmCommandBuilder: build_upgrade_command Tests ===

    #[test]
    fn test_helm_build_upgrade_all_options() {
        let mut set_values = HashMap::new();
        set_values.insert("image.tag".to_string(), "v2.0".to_string());
        set_values.insert("replicas".to_string(), "3".to_string());
        let values_files = vec![
            "/tmp/values.yaml".to_string(),
            "/tmp/override.yaml".to_string(),
        ];

        let cmd = HelmCommandBuilder::build_upgrade_command(
            Some("helm"),
            None,
            "my-release",
            "my-chart",
            Some("production"),
            Some(&set_values),
            Some(&values_files),
            Some("client"),
            true,
            Some("5m"),
            true,
            Some("1.2.3"),
            true,
        );
        assert!(cmd.starts_with("helm upgrade 'my-release' 'my-chart'"));
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains("--set 'image.tag'='v2.0'"));
        assert!(cmd.contains("--set 'replicas'='3'"));
        assert!(cmd.contains("-f '/tmp/values.yaml'"));
        assert!(cmd.contains("-f '/tmp/override.yaml'"));
        assert!(cmd.contains("--dry-run='client'"));
        assert!(cmd.contains("--wait"));
        assert!(cmd.contains("--timeout '5m'"));
        assert!(cmd.contains("--install"));
        assert!(cmd.contains("--version '1.2.3'"));
        assert!(cmd.contains("--create-namespace"));
    }

    #[test]
    fn test_helm_build_upgrade_minimal() {
        let cmd = HelmCommandBuilder::build_upgrade_command(
            Some("helm"),
            None,
            "my-release",
            "my-chart",
            None,
            None,
            None,
            None,
            false,
            None,
            false,
            None,
            false,
        );
        assert_eq!(cmd, "helm upgrade 'my-release' 'my-chart'");
    }

    #[test]
    fn test_helm_build_upgrade_set_values_with_special_chars() {
        let mut set_values = HashMap::new();
        set_values.insert("config.val".to_string(), "it's special".to_string());

        let cmd = HelmCommandBuilder::build_upgrade_command(
            Some("helm"),
            None,
            "rel",
            "chart",
            None,
            Some(&set_values),
            None,
            None,
            false,
            None,
            false,
            None,
            false,
        );
        assert!(cmd.contains("'it'\\''s special'"));
    }

    // ============== HelmCommandBuilder: build_install_command Tests ===

    #[test]
    fn test_helm_build_install_all_options() {
        let mut set_values = HashMap::new();
        set_values.insert("replicas".to_string(), "2".to_string());
        let values_files = vec!["/tmp/values.yaml".to_string()];

        let cmd = HelmCommandBuilder::build_install_command(
            Some("helm"),
            None,
            "my-release",
            "my-chart",
            Some("production"),
            Some(&set_values),
            Some(&values_files),
            Some("server"),
            true,
            true,
            Some("3.0.0"),
        );
        assert!(cmd.starts_with("helm install 'my-release' 'my-chart'"));
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains("--set 'replicas'='2'"));
        assert!(cmd.contains("-f '/tmp/values.yaml'"));
        assert!(cmd.contains("--dry-run='server'"));
        assert!(cmd.contains("--wait"));
        assert!(cmd.contains("--create-namespace"));
        assert!(cmd.contains("--version '3.0.0'"));
    }

    #[test]
    fn test_helm_build_install_minimal() {
        let cmd = HelmCommandBuilder::build_install_command(
            Some("helm"),
            None,
            "my-release",
            "my-chart",
            None,
            None,
            None,
            None,
            false,
            false,
            None,
        );
        assert_eq!(cmd, "helm install 'my-release' 'my-chart'");
    }

    // ============== HelmCommandBuilder: build_rollback_command Tests ==

    #[test]
    fn test_helm_build_rollback_all_options() {
        let cmd = HelmCommandBuilder::build_rollback_command(
            Some("helm"),
            None,
            "my-release",
            Some(2),
            Some("production"),
            Some("client"),
            true,
        );
        assert!(cmd.starts_with("helm rollback 'my-release'"));
        assert!(cmd.contains(" 2"));
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains("--dry-run='client'"));
        assert!(cmd.contains("--wait"));
    }

    #[test]
    fn test_helm_build_rollback_minimal() {
        let cmd = HelmCommandBuilder::build_rollback_command(
            Some("helm"),
            None,
            "my-release",
            None,
            None,
            None,
            false,
        );
        assert_eq!(cmd, "helm rollback 'my-release'");
    }

    #[test]
    fn test_helm_build_rollback_no_wait() {
        let cmd = HelmCommandBuilder::build_rollback_command(
            Some("helm"),
            None,
            "my-release",
            Some(1),
            None,
            None,
            false,
        );
        assert!(!cmd.contains("--wait"));
    }

    // ============== HelmCommandBuilder: build_history_command Tests ===

    #[test]
    fn test_helm_build_history_all_options() {
        let cmd = HelmCommandBuilder::build_history_command(
            Some("helm"),
            None,
            "my-release",
            Some("staging"),
            Some("yaml"),
        );
        assert!(cmd.starts_with("helm history 'my-release'"));
        assert!(cmd.contains("-n 'staging'"));
        assert!(cmd.contains("-o 'yaml'"));
    }

    #[test]
    fn test_helm_build_history_minimal() {
        let cmd =
            HelmCommandBuilder::build_history_command(Some("helm"), None, "my-release", None, None);
        assert_eq!(cmd, "helm history 'my-release'");
    }

    // ============== HelmCommandBuilder: build_uninstall_command Tests =

    #[test]
    fn test_helm_build_uninstall_all_options() {
        let cmd = HelmCommandBuilder::build_uninstall_command(
            Some("helm"),
            None,
            "my-release",
            Some("production"),
            true,
            true,
        );
        assert!(cmd.starts_with("helm uninstall 'my-release'"));
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains("--dry-run"));
        assert!(cmd.contains("--keep-history"));
    }

    #[test]
    fn test_helm_build_uninstall_minimal() {
        let cmd = HelmCommandBuilder::build_uninstall_command(
            Some("helm"),
            None,
            "my-release",
            None,
            false,
            false,
        );
        assert_eq!(cmd, "helm uninstall 'my-release'");
    }

    #[test]
    fn test_helm_build_uninstall_dry_run_only() {
        let cmd = HelmCommandBuilder::build_uninstall_command(
            Some("helm"),
            None,
            "my-release",
            None,
            true,
            false,
        );
        assert!(cmd.contains("--dry-run"));
        assert!(!cmd.contains("--keep-history"));
    }

    #[test]
    fn test_helm_build_uninstall_keep_history_only() {
        let cmd = HelmCommandBuilder::build_uninstall_command(
            Some("helm"),
            None,
            "my-release",
            None,
            false,
            true,
        );
        assert!(!cmd.contains("--dry-run"));
        assert!(cmd.contains("--keep-history"));
    }

    // ============== Cross-cutting: auto-detect with builders ==========

    #[test]
    fn test_kubernetes_get_with_auto_detect() {
        let cmd = KubernetesCommandBuilder::build_get_command(
            None,
            "pods",
            None,
            Some("default"),
            false,
            None,
            None,
            Some("wide"),
            None,
        );
        assert!(cmd.contains("command -v kubectl"));
        assert!(cmd.contains("get 'pods'"));
        assert!(cmd.contains("-n 'default'"));
        assert!(cmd.contains("-o 'wide'"));
    }

    #[test]
    fn test_helm_upgrade_with_auto_detect() {
        let cmd = HelmCommandBuilder::build_upgrade_command(
            None, None, "rel", "chart", None, None, None, None, false, None, false, None, false,
        );
        assert!(cmd.contains("command -v helm"));
        assert!(cmd.contains("upgrade 'rel' 'chart'"));
    }

    // ============== Edge Case Tests ==============

    #[test]
    fn test_build_apply_command_inline_yaml_with_single_quotes() {
        let yaml = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n  annotations:\n    note: \"it's a test\"";
        let cmd = KubernetesCommandBuilder::build_apply_command(
            Some("kubectl"),
            yaml,
            None,
            None,
            false,
            false,
        );
        // Should not break the shell command - quotes should be escaped
        assert!(cmd.contains("echo"));
        assert!(cmd.contains("kubectl apply"));
    }

    #[test]
    fn test_helm_upgrade_empty_set_values() {
        let empty: HashMap<String, String> = HashMap::new();
        let cmd = HelmCommandBuilder::build_upgrade_command(
            Some("helm"),
            None,
            "my-release",
            "my-chart",
            None,
            Some(&empty),
            None,
            None,
            false,
            None,
            false,
            None,
            false,
        );
        // Empty set_values should not add any --set flags
        assert!(!cmd.contains("--set"));
        assert!(cmd.contains("upgrade 'my-release' 'my-chart'"));
    }

    #[test]
    fn test_helm_install_empty_set_values() {
        let empty: HashMap<String, String> = HashMap::new();
        let cmd = HelmCommandBuilder::build_install_command(
            Some("helm"),
            None,
            "my-release",
            "my-chart",
            None,
            Some(&empty),
            None,
            None,
            false,
            false,
            None,
        );
        assert!(!cmd.contains("--set"));
        assert!(cmd.contains("install 'my-release' 'my-chart'"));
    }

    #[test]
    fn test_validate_delete_ns_uppercase_shorthand() {
        // NS shorthand should also be caught (case insensitive)
        let result = KubernetesCommandBuilder::validate_delete("NS", "kube-system");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_scale_command_zero_replicas_myapp() {
        let cmd = KubernetesCommandBuilder::build_scale_command(
            Some("kubectl"),
            "deployment/myapp",
            0,
            None,
        );
        assert!(cmd.contains("--replicas=0"));
    }

    // ============== Security: Injection Prevention Tests ==============

    #[test]
    fn test_kubectl_bin_injection_falls_back_to_autodetect() {
        let prefix = kubectl_detect_prefix(Some("echo pwned #"));
        // Should fall back to auto-detect (contains command -v)
        assert!(prefix.contains("command -v kubectl"));
    }

    #[test]
    fn test_helm_bin_injection_falls_back_to_autodetect() {
        let prefix = helm_detect_prefix(Some("echo pwned; rm -rf /"));
        assert!(prefix.contains("command -v helm"));
    }

    #[test]
    fn test_valid_binary_paths_accepted() {
        assert!(is_valid_binary_path("kubectl"));
        assert!(is_valid_binary_path("/usr/local/bin/kubectl"));
        assert!(is_valid_binary_path("k3s"));
        assert!(is_valid_binary_path("/snap/bin/microk8s.kubectl"));
    }

    #[test]
    fn test_invalid_binary_paths_rejected() {
        assert!(!is_valid_binary_path("echo pwned #"));
        assert!(!is_valid_binary_path("kubectl; rm -rf /"));
        assert!(!is_valid_binary_path("$(whoami)"));
        assert!(!is_valid_binary_path(""));
        assert!(!is_valid_binary_path("kubectl && cat /etc/passwd"));
    }

    #[test]
    fn test_exec_command_injection_prevented() {
        let cmd = KubernetesCommandBuilder::build_exec_command(
            Some("kubectl"),
            "my-pod",
            "ls; rm -rf /",
            None,
            None,
        );
        // Command should be wrapped in sh -c with shell_escape
        assert!(cmd.contains("-- sh -c 'ls; rm -rf /'"));
        // Should NOT contain unescaped semicolons
        assert!(!cmd.contains("-- ls; rm -rf /"));
    }

    // ============== Helm kubeconfig Tests ==============

    #[test]
    fn test_helm_kubeconfig_prefix_valid() {
        let prefix = kubeconfig_env_prefix(Some("/etc/rancher/k3s/k3s.yaml"));
        assert_eq!(prefix, "KUBECONFIG=/etc/rancher/k3s/k3s.yaml ");
    }

    #[test]
    fn test_helm_kubeconfig_prefix_none() {
        let prefix = kubeconfig_env_prefix(None);
        assert_eq!(prefix, "");
    }

    #[test]
    fn test_helm_kubeconfig_injection_rejected() {
        // Paths with shell metacharacters should be silently ignored
        let prefix = kubeconfig_env_prefix(Some("/tmp/config; rm -rf /"));
        assert_eq!(prefix, "");
    }

    #[test]
    fn test_helm_list_with_kubeconfig() {
        let cmd = HelmCommandBuilder::build_list_command(
            Some("helm"),
            Some("/etc/rancher/k3s/k3s.yaml"),
            None,
            false,
            false,
            None,
            None,
        );
        assert!(cmd.starts_with("KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm"));
        assert!(cmd.contains("list"));
    }

    #[test]
    fn test_helm_kubeconfig_with_auto_detect() {
        let cmd = HelmCommandBuilder::build_list_command(
            None,
            Some("/etc/rancher/k3s/k3s.yaml"),
            None,
            false,
            false,
            None,
            None,
        );
        assert!(cmd.starts_with("KUBECONFIG=/etc/rancher/k3s/k3s.yaml "));
        assert!(cmd.contains("command -v helm"));
    }

    // ============== build_wait_command Tests ==============

    #[test]
    fn test_build_wait_command_primary() {
        let cmd = KubernetesCommandBuilder::build_wait_command(
            Some("kubectl"),
            "pod",
            Some("my-pod"),
            "condition=Ready",
            Some("default"),
            false,
            None,
            Some("60s"),
        );
        assert!(cmd.contains("wait 'pod' 'my-pod'"), "cmd={cmd}");
        assert!(cmd.contains("--for='condition=Ready'"), "cmd={cmd}");
        assert!(cmd.contains("-n 'default'"), "cmd={cmd}");
        assert!(cmd.contains("--timeout='60s'"), "cmd={cmd}");
    }

    #[test]
    fn test_build_wait_command_with_selector() {
        let cmd = KubernetesCommandBuilder::build_wait_command(
            Some("kubectl"),
            "pod",
            None,
            "condition=Ready",
            None,
            false,
            Some("app=web"),
            None,
        );
        assert!(cmd.contains("wait 'pod'"), "cmd={cmd}");
        assert!(cmd.contains("--for='condition=Ready'"), "cmd={cmd}");
        assert!(cmd.contains("-l 'app=web'"), "cmd={cmd}");
        assert!(!cmd.contains("--timeout="), "cmd={cmd}");
    }

    #[test]
    fn test_build_wait_command_all_namespaces() {
        let cmd = KubernetesCommandBuilder::build_wait_command(
            Some("kubectl"),
            "job",
            None,
            "condition=complete",
            None,
            true,
            None,
            Some("120s"),
        );
        assert!(cmd.contains(" -A"), "cmd={cmd}");
        assert!(cmd.contains("--timeout='120s'"), "cmd={cmd}");
    }

    #[test]
    fn test_build_wait_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_wait_command(
            Some("kubectl"),
            "pod",
            None,
            "condition=Ready",
            None,
            false,
            None,
            None,
        );
        assert_eq!(cmd, "kubectl wait 'pod' --for='condition=Ready'");
    }

    // ============== HelmCommandBuilder::build_template_command Tests ==============

    #[test]
    fn test_build_template_command() {
        let mut set_values = std::collections::HashMap::new();
        set_values.insert("image.tag".to_string(), "v2".to_string());
        let values_files = vec!["/tmp/v.yaml".to_string()];
        let show_only = vec!["templates/deployment.yaml".to_string()];

        let cmd = HelmCommandBuilder::build_template_command(
            Some("helm"),
            None,
            "rel",
            "repo/chart",
            None,
            Some(&set_values),
            Some(&values_files),
            Some("1.2.3"),
            Some(&show_only),
        );

        assert!(cmd.contains("template 'rel' 'repo/chart'"), "cmd={cmd}");
        assert!(cmd.contains("--set 'image.tag'='v2'"), "cmd={cmd}");
        assert!(cmd.contains("-f '/tmp/v.yaml'"), "cmd={cmd}");
        assert!(cmd.contains("--version '1.2.3'"), "cmd={cmd}");
        assert!(
            cmd.contains("--show-only 'templates/deployment.yaml'"),
            "cmd={cmd}"
        );
    }

    // ============== HelmCommandBuilder::build_get_command Tests ==============

    #[test]
    fn test_build_helm_get_command() {
        let cmd = HelmCommandBuilder::build_get_command(
            Some("helm"),
            None,
            "values",
            "rel",
            Some("prod"),
            Some(2),
        );
        assert!(cmd.contains("get 'values' 'rel'"), "cmd={cmd}");
        assert!(cmd.contains("-n 'prod'"), "cmd={cmd}");
        assert!(cmd.contains("--revision 2"), "cmd={cmd}");
    }

    #[test]
    fn test_validate_helm_get_subcommand() {
        assert!(KubernetesCommandBuilder::validate_helm_get_subcommand("values").is_ok());
        assert!(KubernetesCommandBuilder::validate_helm_get_subcommand("all").is_ok());
        assert!(KubernetesCommandBuilder::validate_helm_get_subcommand("manifest").is_ok());
        assert!(KubernetesCommandBuilder::validate_helm_get_subcommand("hooks").is_ok());
        assert!(KubernetesCommandBuilder::validate_helm_get_subcommand("notes").is_ok());

        let err = KubernetesCommandBuilder::validate_helm_get_subcommand("delete").unwrap_err();
        match err {
            crate::error::BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("delete"), "reason={reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_kubectl_context_flag() {
        assert_eq!(kubectl_context_flag(None), "");
        assert_eq!(kubectl_context_flag(Some("prod")), " --context=prod");
        assert_eq!(kubectl_context_flag(Some("my ctx")), " --context='my ctx'");
    }

    #[test]
    fn test_validate_context_rejects_flag_like() {
        assert!(validate_context("--kubeconfig=/etc/x").is_err());
        assert!(validate_context("good-ctx").is_ok());
        assert!(validate_context("").is_err());
        // Injection payloads must be rejected by the charset guard.
        assert!(validate_context("prod$(evil)").is_err());
        assert!(validate_context("prod;rm -rf /").is_err());
        // In-charset / space values stay valid.
        assert!(validate_context("prod").is_ok());
        assert!(validate_context("my ctx").is_ok());
    }

    #[test]
    fn test_build_set_command_image() {
        let cmd = KubernetesCommandBuilder::build_set_command(
            Some("kubectl"),
            "image",
            "deployment/api",
            &["app=nginx:1.27".to_string()],
            Some("prod"),
            Some("east"),
        );
        assert!(
            cmd.contains("set 'image' 'deployment/api' 'app=nginx:1.27'"),
            "cmd: {cmd}"
        );
        assert!(cmd.contains("-n 'prod'"), "cmd: {cmd}");
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }

    // ============== build_cordon_command Tests ==============

    #[test]
    fn test_build_cordon_command() {
        assert!(
            KubernetesCommandBuilder::build_cordon_command(Some("kubectl"), "node-1", true, None)
                .contains("cordon 'node-1'")
        );
        let unc = KubernetesCommandBuilder::build_cordon_command(
            Some("kubectl"),
            "node-1",
            false,
            Some("east"),
        );
        assert!(
            unc.contains("uncordon 'node-1' --context=east"),
            "cmd: {unc}"
        );
    }

    // ============== build_patch_command Tests ==============

    #[test]
    fn test_build_patch_command_merge() {
        let cmd = KubernetesCommandBuilder::build_patch_command(
            Some("kubectl"),
            "deployment/api",
            r#"{"spec":{"replicas":3}}"#,
            "merge",
            Some("prod"),
            None,
        );
        assert!(
            cmd.contains("patch 'deployment/api' --type='merge' -p"),
            "cmd: {cmd}"
        );
        assert!(cmd.contains("-n 'prod'"), "cmd: {cmd}");
    }

    // ============== build_drain_command Tests ==============

    #[test]
    fn test_build_drain_command() {
        let cmd = KubernetesCommandBuilder::build_drain_command(
            Some("kubectl"),
            "node-1",
            true,
            true,
            false,
            Some("east"),
        );
        assert!(cmd.contains("drain 'node-1'"), "cmd: {cmd}");
        assert!(cmd.contains("--ignore-daemonsets"), "cmd: {cmd}");
        assert!(cmd.contains("--delete-emptydir-data"), "cmd: {cmd}");
        assert!(!cmd.contains("--force"), "cmd: {cmd}");
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }

    // ============== build_auth_can_i_command Tests ==============

    #[test]
    fn test_build_auth_can_i_command() {
        let cmd = KubernetesCommandBuilder::build_auth_can_i_command(
            Some("kubectl"),
            "create",
            "deployments",
            Some("prod"),
            Some("system:serviceaccount:ci:deployer"),
            None,
        );
        assert!(
            cmd.contains("auth can-i 'create' 'deployments'"),
            "cmd: {cmd}"
        );
        assert!(cmd.contains("-n 'prod'"), "cmd: {cmd}");
        assert!(
            cmd.contains("--as 'system:serviceaccount:ci:deployer'"),
            "cmd: {cmd}"
        );
    }

    // ============== validate_raw_path Tests ==============

    #[test]
    fn test_validate_raw_path_reject_empty() {
        assert!(validate_raw_path("").is_err());
    }

    #[test]
    fn test_validate_raw_path_reject_no_leading_slash() {
        assert!(validate_raw_path("readyz").is_err());
        assert!(validate_raw_path("api/v1").is_err());
    }

    #[test]
    fn test_validate_raw_path_reject_dotdot_segment() {
        assert!(validate_raw_path("/foo/../bar").is_err());
        assert!(validate_raw_path("/../etc").is_err());
    }

    #[test]
    fn test_validate_raw_path_reject_space() {
        assert!(validate_raw_path("/foo bar").is_err());
    }

    #[test]
    fn test_validate_raw_path_reject_shell_metachar_dollar() {
        assert!(validate_raw_path("/foo$x").is_err());
    }

    #[test]
    fn test_validate_raw_path_reject_shell_metachar_semicolon() {
        assert!(validate_raw_path("/foo;rm").is_err());
    }

    #[test]
    fn test_validate_raw_path_reject_shell_metachar_pipe() {
        assert!(validate_raw_path("/foo|cat").is_err());
    }

    #[test]
    fn test_validate_raw_path_reject_backtick() {
        assert!(validate_raw_path("/foo`cmd`").is_err());
    }

    #[test]
    fn test_validate_raw_path_accept_healthz() {
        assert!(validate_raw_path("/healthz").is_ok());
        assert!(validate_raw_path("/livez").is_ok());
        assert!(validate_raw_path("/readyz").is_ok());
        assert!(validate_raw_path("/readyz?verbose").is_ok());
    }

    #[test]
    fn test_validate_raw_path_accept_api_paths() {
        assert!(validate_raw_path("/api/v1").is_ok());
        assert!(validate_raw_path("/apis/apps/v1").is_ok());
    }
}
