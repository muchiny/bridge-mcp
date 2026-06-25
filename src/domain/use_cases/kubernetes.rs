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

/// Validate a Kubernetes secret type.
///
/// # Errors
/// Returns `BridgeError::CommandDenied` if `t` is not one of
/// `opaque`, `generic`, `tls`, or `docker-registry` (case-insensitive).
pub fn validate_secret_type(t: &str) -> Result<()> {
    match t.to_lowercase().as_str() {
        "opaque" | "generic" | "tls" | "docker-registry" => Ok(()),
        _ => Err(BridgeError::CommandDenied {
            reason: format!(
                "invalid secret type '{t}'; must be one of: Opaque/generic, tls, docker-registry"
            ),
        }),
    }
}

/// Validate a Kubernetes secret/configmap data key.
///
/// Keys must be non-empty, must not start with `-` (flag injection guard),
/// and may only contain `[-._a-zA-Z0-9]`.
///
/// # Errors
/// Returns `BridgeError::CommandDenied` on invalid keys.
pub fn validate_secret_key(k: &str) -> Result<()> {
    if k.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "key must not be empty".to_string(),
        });
    }
    if k.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("key must not start with '-' (flag injection guard): {k}"),
        });
    }
    if !k
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("key contains disallowed characters: {k}"),
        });
    }
    Ok(())
}

/// Validate a key used inside a jsonpath `{.data['KEY']}` expression.
///
/// Rejects all characters that could escape the double-quoted jsonpath context:
/// single quote, double quote, backslash, `$`, and backtick, in addition to
/// the base [`validate_secret_key`] restrictions.
///
/// # Errors
/// Returns `BridgeError::CommandDenied` on invalid keys.
pub fn validate_jsonpath_key(k: &str) -> Result<()> {
    validate_secret_key(k)?;
    for ch in k.chars() {
        if matches!(ch, '\'' | '"' | '\\' | '$' | '`') {
            return Err(BridgeError::CommandDenied {
                reason: format!("key contains character '{ch}' unsafe in jsonpath context: {k}"),
            });
        }
    }
    Ok(())
}

/// Validate a generic Kubernetes RBAC resource name.
///
/// Non-empty, ≤253 chars, charset `[a-z0-9.-]`, must not start with `'-'`.
/// Covers roles, clusterroles, rolebindings, clusterrolebindings, and service accounts.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] on invalid name.
pub fn validate_rbac_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "RBAC resource name must not be empty".to_string(),
        });
    }
    if name.len() > 253 {
        return Err(BridgeError::CommandDenied {
            reason: format!("RBAC resource name exceeds 253 chars: {name}"),
        });
    }
    if name.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("RBAC resource name must not start with '-': {name}"),
        });
    }
    if !name
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '.' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("RBAC resource name contains disallowed characters: {name}"),
        });
    }
    Ok(())
}

/// Validate a Kubernetes service account name.
///
/// Non-empty, ≤253 chars, charset [a-z0-9.-], must not start with '-'.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] on invalid name.
pub fn validate_sa_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "service account name must not be empty".to_string(),
        });
    }
    if name.len() > 253 {
        return Err(BridgeError::CommandDenied {
            reason: format!("service account name exceeds 253 chars: {name}"),
        });
    }
    if name.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("service account name must not start with '-': {name}"),
        });
    }
    if !name
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '.' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("service account name contains disallowed characters: {name}"),
        });
    }
    Ok(())
}

/// Validate a token duration string.
///
/// Must match `^[0-9]+(s|m|h)$`.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] on invalid duration.
pub fn validate_duration(d: &str) -> Result<()> {
    if d.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "duration must not be empty".to_string(),
        });
    }
    let (digits, suffix) = match d.rfind(|c: char| c.is_ascii_digit()) {
        Some(pos) => (&d[..=pos], &d[pos + 1..]),
        None => {
            return Err(BridgeError::CommandDenied {
                reason: format!("duration has no numeric prefix: {d}"),
            });
        }
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(BridgeError::CommandDenied {
            reason: format!("duration numeric part is invalid: {d}"),
        });
    }
    if !matches!(suffix, "s" | "m" | "h") {
        return Err(BridgeError::CommandDenied {
            reason: format!("duration suffix must be one of s/m/h, got: '{suffix}' in {d}"),
        });
    }
    Ok(())
}

/// Validate an RBAC kind against an allowlist.
///
/// Case-sensitive membership check.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] if `kind` is not in `allowed`.
pub fn validate_rbac_kind(kind: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&kind) {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!("RBAC kind '{kind}' is not allowed; allowed: {allowed:?}"),
        })
    }
}

/// Validate a server URL for kubeconfig generation.
///
/// Must start with `https://`, use only safe chars, no whitespace or shell metachars.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] on invalid URL.
pub fn validate_url(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        return Err(BridgeError::CommandDenied {
            reason: format!("server URL must start with 'https://': {url}"),
        });
    }
    for ch in url.chars() {
        if ch.is_ascii_whitespace() {
            return Err(BridgeError::CommandDenied {
                reason: format!("server URL must not contain whitespace: {url}"),
            });
        }
        if matches!(ch, ';' | '$' | '`' | '(') {
            return Err(BridgeError::CommandDenied {
                reason: format!("server URL contains shell metacharacter '{ch}': {url}"),
            });
        }
        if !ch.is_ascii() {
            return Err(BridgeError::CommandDenied {
                reason: format!("server URL must contain only ASCII characters: {url}"),
            });
        }
        if !matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | ':' | '/' | '%' | '-') {
            return Err(BridgeError::CommandDenied {
                reason: format!("server URL contains disallowed character '{ch}': {url}"),
            });
        }
    }
    Ok(())
}

/// Validate a token or RBAC verb/resource string.
///
/// Non-empty, charset `[A-Za-z0-9.*/_-]`, no shell metachars, no leading '-'.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] on invalid value.
pub fn validate_rbac_token(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "value must not be empty".to_string(),
        });
    }
    if s.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("value must not start with '-': {s}"),
        });
    }
    if !s
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '*' | '/' | '_' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("value contains disallowed characters: {s}"),
        });
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
    /// [--sort-by={sort}] [--show-labels] [--show-kind]
    /// [--chunk-size={N}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::fn_params_excessive_bools)]
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
        raw: bool,
        show_labels: bool,
        show_kind: bool,
        chunk_size: Option<u64>,
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
        } else if raw {
            cmd.push_str(" -o json");
        }

        if let Some(sort) = sort_by {
            let _ = write!(cmd, " --sort-by={}", shell_escape(sort));
        }

        if show_labels {
            cmd.push_str(" --show-labels");
        }

        if show_kind {
            cmd.push_str(" --show-kind");
        }

        if let Some(cs) = chunk_size {
            let _ = write!(cmd, " --chunk-size={cs}");
        }

        cmd
    }

    /// Build a `kubectl get events` command sorted by last timestamp.
    ///
    /// Constructs: `{kubectl} get events --sort-by=.lastTimestamp [-n {ns}]
    /// [-A] [--field-selector {fs}] [-l {sel}] [--for {target}] [-o {out}]`
    #[must_use]
    pub fn build_events_command(
        kubectl_bin: Option<&str>,
        namespace: Option<&str>,
        all_namespaces: bool,
        field_selector: Option<&str>,
        output: Option<&str>,
        label_selector: Option<&str>,
        for_target: Option<&str>,
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
        if let Some(sel) = label_selector {
            let _ = write!(cmd, " -l {}", shell_escape(sel));
        }
        if let Some(ft) = for_target {
            let _ = write!(cmd, " --for {}", shell_escape(ft));
        }
        if let Some(out) = output {
            let _ = write!(cmd, " -o {}", shell_escape(out));
        }
        cmd
    }

    /// Build a `kubectl logs` command.
    ///
    /// Constructs: `{kubectl} logs {pod} [-n {ns}] [-c {container}]
    /// [--tail={N}] [--since={dur}] [-p] [--timestamps]
    /// [-l {selector}] [--all-containers] [--max-log-requests={N}]
    /// [--prefix] [--since-time={t}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::fn_params_excessive_bools)]
    pub fn build_logs_command(
        kubectl_bin: Option<&str>,
        pod: &str,
        namespace: Option<&str>,
        container: Option<&str>,
        tail: Option<u64>,
        since: Option<&str>,
        previous: bool,
        timestamps: bool,
        label_selector: Option<&str>,
        all_containers: bool,
        max_log_requests: Option<u64>,
        prefix: bool,
        since_time: Option<&str>,
    ) -> String {
        let prefix_str = kubectl_detect_prefix(kubectl_bin);
        let escaped_pod = shell_escape(pod);
        let mut cmd = format!("{prefix_str}logs {escaped_pod}");

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

        if let Some(sel) = label_selector {
            let _ = write!(cmd, " -l {}", shell_escape(sel));
        }

        if all_containers {
            cmd.push_str(" --all-containers");
        }

        if let Some(n) = max_log_requests {
            let _ = write!(cmd, " --max-log-requests={n}");
        }

        if prefix {
            cmd.push_str(" --prefix");
        }

        if let Some(t) = since_time {
            let _ = write!(cmd, " --since-time={}", shell_escape(t));
        }

        cmd
    }

    /// Build a `kubectl describe` command.
    ///
    /// Constructs: `{kubectl} describe {resource} [{name}] [-l {sel}] [-n {ns}] [-A]`
    #[must_use]
    pub fn build_describe_command(
        kubectl_bin: Option<&str>,
        resource: &str,
        name: Option<&str>,
        namespace: Option<&str>,
        label_selector: Option<&str>,
        all_namespaces: bool,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_resource = shell_escape(resource);
        let mut cmd = format!("{prefix}describe {escaped_resource}");

        if let Some(n) = name {
            let _ = write!(cmd, " {}", shell_escape(n));
        }

        if let Some(sel) = label_selector {
            let _ = write!(cmd, " -l {}", shell_escape(sel));
        }

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if all_namespaces {
            cmd.push_str(" -A");
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
    /// Constructs: `{kubectl} delete {resource} [{name}] [-l {sel}]
    /// [--field-selector {fs}] [--all] [-n {ns}]
    /// [--grace-period={N}] [--force] [--dry-run={mode}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_delete_command(
        kubectl_bin: Option<&str>,
        resource: &str,
        name: Option<&str>,
        namespace: Option<&str>,
        grace_period: Option<u64>,
        force: bool,
        dry_run: Option<&str>,
        label_selector: Option<&str>,
        all: bool,
        field_selector: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let escaped_resource = shell_escape(resource);
        let mut cmd = format!("{prefix}delete {escaped_resource}");

        if let Some(n) = name {
            let _ = write!(cmd, " {}", shell_escape(n));
        }

        if let Some(sel) = label_selector {
            let _ = write!(cmd, " -l {}", shell_escape(sel));
        }

        if let Some(fs) = field_selector {
            let _ = write!(cmd, " --field-selector {}", shell_escape(fs));
        }

        if all {
            cmd.push_str(" --all");
        }

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
    /// [--to-revision={N}] [-l {sel}] [--watch={bool}] [--timeout={t}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_rollout_command(
        kubectl_bin: Option<&str>,
        action: &str,
        resource: &str,
        namespace: Option<&str>,
        to_revision: Option<u64>,
        watch: Option<bool>,
        timeout: Option<&str>,
        label_selector: Option<&str>,
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

        if let Some(sel) = label_selector {
            let _ = write!(cmd, " -l {}", shell_escape(sel));
        }

        if let Some(w) = watch {
            let _ = write!(cmd, " --watch={w}");
        }

        if let Some(t) = timeout {
            let _ = write!(cmd, " --timeout={}", shell_escape(t));
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
    /// Constructs: `{kubectl} exec [-i] {pod} [-n {ns}] [-c {container}]
    /// -- {argv...}` or `-- sh -c {command}`
    #[must_use]
    pub fn build_exec_command(
        kubectl_bin: Option<&str>,
        pod: &str,
        command: Option<&str>,
        namespace: Option<&str>,
        container: Option<&str>,
        argv: Option<&[String]>,
        stdin: bool,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}exec");

        if stdin {
            cmd.push_str(" -i");
        }

        let _ = write!(cmd, " {}", shell_escape(pod));

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        if let Some(c) = container {
            let _ = write!(cmd, " -c {}", shell_escape(c));
        }

        if let Some(args) = argv {
            cmd.push_str(" --");
            for arg in args {
                let _ = write!(cmd, " {}", shell_escape(arg));
            }
        } else if let Some(c) = command {
            let _ = write!(cmd, " -- sh -c {}", shell_escape(c));
        }

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
        let allowed = ["all", "values", "manifest", "hooks", "notes", "metadata"];
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
    /// [--from={from}] [--env-file={ef}] [--list] [-n {ns}] [--context={ctx}]`
    ///
    /// `subcommand` is one of `image`, `env`, `resources` (validated by the
    /// handler before this builder is called).
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_set_command(
        kubectl_bin: Option<&str>,
        subcommand: &str,
        target: &str,
        assignments: &[String],
        namespace: Option<&str>,
        context: Option<&str>,
        list: bool,
        from: Option<&str>,
        env_file: Option<&str>,
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
        if let Some(f) = from {
            let _ = write!(cmd, " --from={}", shell_escape(f));
        }
        if let Some(ef) = env_file {
            let _ = write!(cmd, " --env-file={}", shell_escape(ef));
        }
        if list {
            cmd.push_str(" --list");
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

    /// Validate a label selector for safety.
    pub fn validate_label_selector(sel: &str) -> Result<()> {
        if sel.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Label selector cannot be empty".to_string(),
            });
        }
        if sel.starts_with('-') {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Label selector '{sel}' rejected: starts with '-' (possible flag injection)"
                ),
            });
        }
        let valid = sel.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '.' | '_' | '/' | '=' | ',' | '!' | '(' | ')' | '-' | ' ' | '@' | ':'
                )
        });
        if !valid {
            return Err(BridgeError::CommandDenied {
                reason: format!("Label selector '{sel}' contains invalid characters"),
            });
        }
        Ok(())
    }

    /// Validate output format for `kubectl get events`.
    pub fn validate_events_output(out: &str) -> Result<()> {
        let allowed = ["json", "yaml", "wide", "name"];
        if allowed.contains(&out) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Events output format '{out}' is not allowed. Allowed: {allowed:?}"
                ),
            })
        }
    }

    /// Validate a `--for` target (kind/name) for `kubectl get events`.
    pub fn validate_for_target(kind: &str, name: &str) -> Result<()> {
        if kind.is_empty() || name.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "for_kind and for_name must both be non-empty".to_string(),
            });
        }
        let valid_kind = kind
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        let valid_name = name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if !valid_kind || !valid_name {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "for_kind '{kind}' or for_name '{name}' contains invalid characters"
                ),
            });
        }
        Ok(())
    }

    /// Validate that a delete operation has exactly one target specifier.
    pub fn validate_delete_target(
        resource: &str,
        name: Option<&str>,
        label_selector: Option<&str>,
        field_selector: Option<&str>,
        all: bool,
    ) -> Result<()> {
        let has_name = name.is_some();
        let has_selector = label_selector.is_some() || field_selector.is_some();
        if has_name && all {
            return Err(BridgeError::CommandDenied {
                reason: "Cannot use both name and --all".to_string(),
            });
        }
        if !has_name && !has_selector && !all {
            return Err(BridgeError::CommandDenied {
                reason: "Must specify at least one of: name, label_selector, field_selector, or all=true".to_string(),
            });
        }
        if all {
            let lower = resource.to_lowercase();
            if lower == "namespace" || lower == "ns" {
                return Err(BridgeError::CommandDenied {
                    reason: "Cannot use --all with namespace resource (blast-radius guard)"
                        .to_string(),
                });
            }
        }
        Ok(())
    }

    /// Validate that exec invocation has exactly one of command or argv.
    pub fn validate_exec_invocation(command: Option<&str>, argv: Option<&[String]>) -> Result<()> {
        match (command, argv) {
            (Some(_), None) => Ok(()),
            (None, Some(elems)) => {
                if elems.is_empty() {
                    return Err(BridgeError::CommandDenied {
                        reason: "argv must not be empty".to_string(),
                    });
                }
                if elems.iter().any(String::is_empty) {
                    return Err(BridgeError::CommandDenied {
                        reason: "argv elements must not be empty".to_string(),
                    });
                }
                Ok(())
            }
            (Some(_), Some(_)) => Err(BridgeError::CommandDenied {
                reason: "Exactly one of command or argv must be provided, not both".to_string(),
            }),
            (None, None) => Err(BridgeError::CommandDenied {
                reason: "Either command or argv must be provided".to_string(),
            }),
        }
    }

    /// Validate `from` for `kubectl set env --from`.
    pub fn validate_set_from(from: &str) -> Result<()> {
        let (prefix, name) = from
            .split_once('/')
            .ok_or_else(|| BridgeError::CommandDenied {
                reason: format!("from '{from}' must be configmap/NAME or secret/NAME"),
            })?;
        if prefix != "configmap" && prefix != "secret" {
            return Err(BridgeError::CommandDenied {
                reason: format!("from prefix must be 'configmap' or 'secret', got '{prefix}'"),
            });
        }
        if name.is_empty() || name.starts_with('-') {
            return Err(BridgeError::CommandDenied {
                reason: format!("from name '{name}' is empty or starts with '-'"),
            });
        }
        let valid = name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
        if !valid {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "from name '{name}' contains invalid characters (only lowercase, digits, '.', '-')"
                ),
            });
        }
        Ok(())
    }

    /// Validate that a `kubectl set` invocation has at least one action.
    pub fn validate_set_invocation(
        subcommand: &str,
        assignments: &[String],
        list: bool,
        from: Option<&str>,
        env_file: Option<&str>,
    ) -> Result<()> {
        if assignments.is_empty() && !list && from.is_none() && env_file.is_none() {
            return Err(BridgeError::CommandDenied {
                reason: "Must specify at least one of: assignments, list, from, or env_file"
                    .to_string(),
            });
        }
        if (from.is_some() || env_file.is_some()) && subcommand != "env" {
            return Err(BridgeError::CommandDenied {
                reason: "from and env_file are only valid with subcommand=env".to_string(),
            });
        }
        if from.is_some() && env_file.is_some() {
            return Err(BridgeError::CommandDenied {
                reason: "from and env_file are mutually exclusive".to_string(),
            });
        }
        if list && !assignments.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "list=true and assignments are mutually exclusive".to_string(),
            });
        }
        Ok(())
    }

    /// Build a `kubectl create secret` command.
    ///
    /// Supports generic (`Opaque`), `tls`, and `docker-registry` types.
    /// Secret values are accepted as `&str` at the boundary (callers must
    /// extract via `RedactedSecret::as_str()`) — the command string will
    /// contain plaintext in the host process argv (acceptable for air-gapped
    /// hosts; prefer `--from-file`/`--from-env-file` in sensitive environments).
    ///
    /// # Errors
    /// Returns `BridgeError::CommandDenied` on validation failure.
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::too_many_lines)]
    pub fn build_create_secret_command(
        kubectl_bin: Option<&str>,
        name: &str,
        secret_type: &str,
        from_literal: &[(String, String)],
        from_file: &[String],
        from_env_file: Option<&str>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
        docker_server: Option<&str>,
        docker_username: Option<&str>,
        docker_password: Option<&str>,
        docker_email: Option<&str>,
        namespace: Option<&str>,
        dry_run: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        validate_secret_type(secret_type)?;
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }

        // Validate key names in from_literal
        for (k, _v) in from_literal {
            validate_secret_key(k)?;
        }

        // Validate subtype-specific argument combinations
        let normalized = secret_type.to_lowercase();
        let subcommand = match normalized.as_str() {
            "tls" => "tls",
            "docker-registry" => "docker-registry",
            _ => "generic", // opaque or generic
        };

        match subcommand {
            "tls" => {
                if tls_cert.is_none() || tls_key.is_none() {
                    return Err(BridgeError::CommandDenied {
                        reason: "tls secret requires both tls_cert and tls_key".to_string(),
                    });
                }
                if !from_literal.is_empty() || !from_file.is_empty() {
                    return Err(BridgeError::CommandDenied {
                        reason: "tls secret does not accept from_literal or from_file".to_string(),
                    });
                }
            }
            "docker-registry" => {
                if docker_server.is_none() || docker_username.is_none() || docker_password.is_none()
                {
                    return Err(BridgeError::CommandDenied {
                        reason: "docker-registry secret requires docker_server, docker_username, and docker_password".to_string(),
                    });
                }
                if !from_literal.is_empty() {
                    return Err(BridgeError::CommandDenied {
                        reason: "docker-registry secret does not accept from_literal".to_string(),
                    });
                }
            }
            _ => {
                // generic: forbid tls/docker flags
                if tls_cert.is_some() || tls_key.is_some() {
                    return Err(BridgeError::CommandDenied {
                        reason: "generic secret does not accept tls_cert or tls_key".to_string(),
                    });
                }
                if docker_server.is_some()
                    || docker_username.is_some()
                    || docker_password.is_some()
                    || docker_email.is_some()
                {
                    return Err(BridgeError::CommandDenied {
                        reason: "generic secret does not accept docker_* arguments".to_string(),
                    });
                }
            }
        }

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}create secret {subcommand} {}", shell_escape(name));

        for (k, v) in from_literal {
            // k validated above; v is plaintext at this boundary
            let _ = write!(
                cmd,
                " --from-literal={}={}",
                shell_escape(k),
                shell_escape(v)
            );
        }
        for path in from_file {
            let _ = write!(cmd, " --from-file={}", shell_escape(path));
        }
        if let Some(env_path) = from_env_file {
            let _ = write!(cmd, " --from-env-file={}", shell_escape(env_path));
        }
        if let Some(cert) = tls_cert {
            let _ = write!(cmd, " --cert={}", shell_escape(cert));
        }
        if let Some(key) = tls_key {
            let _ = write!(cmd, " --key={}", shell_escape(key));
        }
        if let Some(srv) = docker_server {
            let _ = write!(cmd, " --docker-server={}", shell_escape(srv));
        }
        if let Some(user) = docker_username {
            let _ = write!(cmd, " --docker-username={}", shell_escape(user));
        }
        if let Some(pw) = docker_password {
            // pw is plaintext at this single audited boundary
            let _ = write!(cmd, " --docker-password={}", shell_escape(pw));
        }
        if let Some(email) = docker_email {
            let _ = write!(cmd, " --docker-email={}", shell_escape(email));
        }
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if let Some(dr) = dry_run {
            let _ = write!(cmd, " --dry-run={}", shell_escape(dr));
        }
        let ctx_flag = kubectl_context_flag(context);
        cmd.push_str(&ctx_flag);
        Ok(cmd)
    }

    /// Build a `kubectl create configmap` command.
    ///
    /// # Errors
    /// Returns `BridgeError::CommandDenied` when no source is given or keys are invalid.
    #[expect(clippy::too_many_arguments)]
    pub fn build_create_configmap_command(
        kubectl_bin: Option<&str>,
        name: &str,
        from_literal: &[(String, String)],
        from_file: &[String],
        from_env_file: Option<&str>,
        namespace: Option<&str>,
        dry_run: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        if from_literal.is_empty() && from_file.is_empty() && from_env_file.is_none() {
            return Err(BridgeError::CommandDenied {
                reason: "at least one of from_literal, from_file, or from_env_file must be set"
                    .to_string(),
            });
        }
        for (k, _v) in from_literal {
            validate_secret_key(k)?;
        }

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}create configmap {}", shell_escape(name));

        for (k, v) in from_literal {
            let _ = write!(
                cmd,
                " --from-literal={}={}",
                shell_escape(k),
                shell_escape(v)
            );
        }
        for path in from_file {
            let _ = write!(cmd, " --from-file={}", shell_escape(path));
        }
        if let Some(env_path) = from_env_file {
            let _ = write!(cmd, " --from-env-file={}", shell_escape(env_path));
        }
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if let Some(dr) = dry_run {
            let _ = write!(cmd, " --dry-run={}", shell_escape(dr));
        }
        let ctx_flag = kubectl_context_flag(context);
        cmd.push_str(&ctx_flag);
        Ok(cmd)
    }

    /// Build a `kubectl get secret` command that lists data keys + base64 lengths.
    ///
    /// The go-template emits `<key>\t<base64-len>\n` per data entry — it
    /// NEVER outputs the value bytes, making this safe to log.
    ///
    /// # Errors
    /// Returns `BridgeError::CommandDenied` on namespace/context validation failure.
    pub fn build_secret_keys_command(
        kubectl_bin: Option<&str>,
        name: &str,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}get secret {}", shell_escape(name));
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        let ctx_flag = kubectl_context_flag(context);
        cmd.push_str(&ctx_flag);
        // go-template: key TAB base64-length NEWLINE — no value bytes
        cmd.push_str(
            r#" -o go-template='{{range $k,$v := .data}}{{$k}}{{"\t"}}{{len $v}}{{"\n"}}{{end}}'"#,
        );
        Ok(cmd)
    }

    /// Build a `kubectl get secret | base64 -d` command (REVEAL-GATED).
    ///
    /// The caller MUST check `reveal == true` before calling this function
    /// and return a `CommandDenied` error if not. The builder itself does NOT
    /// enforce the reveal gate — the builder enforces it as a second layer
    /// (defence in depth). The handler must still gate on `reveal` before
    /// calling this function.
    ///
    /// # Errors
    /// Returns `BridgeError::CommandDenied` when `reveal` is `false`, or on
    /// key/namespace/context validation failure.
    pub fn build_secret_decode_command(
        kubectl_bin: Option<&str>,
        name: &str,
        key: &str,
        namespace: Option<&str>,
        context: Option<&str>,
        reveal: bool,
    ) -> Result<String> {
        if !reveal {
            return Err(crate::error::BridgeError::CommandDenied {
                reason: "secret decode requires reveal=true".into(),
            });
        }
        validate_jsonpath_key(key)?;
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}get secret {}", shell_escape(name));
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        let ctx_flag = kubectl_context_flag(context);
        cmd.push_str(&ctx_flag);
        // key is already validated as safe for jsonpath single-quote indexing
        let _ = write!(cmd, " -o jsonpath=\"{{.data['{key}']}}\" | base64 -d");
        Ok(cmd)
    }

    /// Build a `kubectl get secret -o yaml` command that strips cluster-instance metadata.
    ///
    /// The output is a re-appliable YAML manifest with `creationTimestamp`,
    /// `resourceVersion`, `uid`, `selfLink`, `generation`, `managedFields`,
    /// `last-applied-configuration` annotation, and the `namespace` line removed.
    /// The `.data` block still contains base64-encoded values — treat as secret.
    ///
    /// The builder enforces the reveal gate as a second layer (defence in
    /// depth). The handler must still gate on `reveal` before calling this
    /// function.
    ///
    /// # Errors
    /// Returns `BridgeError::CommandDenied` when `reveal` is `false`, or on
    /// namespace/context validation failure.
    pub fn build_secret_export_command(
        kubectl_bin: Option<&str>,
        name: &str,
        namespace: Option<&str>,
        context: Option<&str>,
        reveal: bool,
    ) -> Result<String> {
        if !reveal {
            return Err(crate::error::BridgeError::CommandDenied {
                reason: "secret export requires reveal=true".into(),
            });
        }
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}get secret {}", shell_escape(name));
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        let ctx_flag = kubectl_context_flag(context);
        cmd.push_str(&ctx_flag);
        // Strip cluster-instance fields so the manifest is re-appliable
        cmd.push_str(
            r" -o yaml | grep -v -E '^\s*(creationTimestamp|resourceVersion|uid|selfLink|generation|managedFields):' | grep -v -E '^\s+(kubectl\.kubernetes\.io/last-applied-configuration|namespace):'",
        );
        Ok(cmd)
    }

    /// Build a `kubectl auth whoami` command.
    ///
    /// Constructs: `{kubectl} auth whoami -o {output}[--context={ctx}]`
    ///
    /// Default output is `yaml`. The `output` parameter is shell-escaped.
    #[must_use]
    pub fn build_auth_whoami_command(
        kubectl_bin: Option<&str>,
        output: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let out = output.unwrap_or("yaml");
        let mut cmd = format!("{prefix}auth whoami -o {}", shell_escape(out));
        cmd.push_str(&kubectl_context_flag(context));
        cmd
    }

    /// Build a `kubectl create token <sa>` command.
    ///
    /// Constructs: `{kubectl} create token {sa} [-n {ns}] [--duration {dur}]
    /// [--audience {aud}...] [--bound-object-kind {kind} --bound-object-name {name}]
    /// [--context={ctx}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_create_token_command(
        kubectl_bin: Option<&str>,
        service_account: &str,
        namespace: Option<&str>,
        duration: Option<&str>,
        audiences: Option<&[String]>,
        bound_object_kind: Option<&str>,
        bound_object_name: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!("{prefix}create token {}", shell_escape(service_account));
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if let Some(dur) = duration {
            let _ = write!(cmd, " --duration {}", shell_escape(dur));
        }
        if let Some(auds) = audiences {
            for aud in auds {
                let _ = write!(cmd, " --audience {}", shell_escape(aud));
            }
        }
        if let Some(kind) = bound_object_kind {
            let _ = write!(cmd, " --bound-object-kind {}", shell_escape(kind));
            if let Some(name) = bound_object_name {
                let _ = write!(cmd, " --bound-object-name {}", shell_escape(name));
            }
        }
        cmd.push_str(&kubectl_context_flag(context));
        cmd
    }

    /// Build a `kubectl create <rbac-kind>` command.
    ///
    /// Supports: role, clusterrole, rolebinding, clusterrolebinding, serviceaccount.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_rbac_create_command(
        kubectl_bin: Option<&str>,
        kind: &str,
        name: &str,
        namespace: Option<&str>,
        verbs: Option<&[String]>,
        resources: Option<&[String]>,
        resource_names: Option<&[String]>,
        clusterrole: Option<&str>,
        role: Option<&str>,
        serviceaccount: Option<&str>,
        user: Option<&str>,
        group: Option<&str>,
        dry_run: bool,
        output: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let mut cmd = format!(
            "{prefix}create {} {}",
            shell_escape(kind),
            shell_escape(name)
        );

        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }

        // role/clusterrole: verbs, resources, resource-names
        if matches!(kind, "role" | "clusterrole") {
            if let Some(vs) = verbs {
                for v in vs {
                    let _ = write!(cmd, " --verb={}", shell_escape(v));
                }
            }
            if let Some(rs) = resources {
                for r in rs {
                    let _ = write!(cmd, " --resource={}", shell_escape(r));
                }
            }
            if let Some(rns) = resource_names {
                for rn in rns {
                    let _ = write!(cmd, " --resource-name={}", shell_escape(rn));
                }
            }
        }

        // rolebinding/clusterrolebinding: role reference + subjects
        if matches!(kind, "rolebinding" | "clusterrolebinding") {
            if let Some(cr) = clusterrole {
                let _ = write!(cmd, " --clusterrole {}", shell_escape(cr));
            } else if let Some(r) = role {
                let _ = write!(cmd, " --role {}", shell_escape(r));
            }
            if let Some(sa) = serviceaccount {
                // Format: ns:name — split on ':', shell-escape each half
                if let Some(colon_pos) = sa.find(':') {
                    let sa_ns = &sa[..colon_pos];
                    let sa_name = &sa[colon_pos + 1..];
                    let _ = write!(
                        cmd,
                        " --serviceaccount={}:{}",
                        shell_escape(sa_ns),
                        shell_escape(sa_name)
                    );
                } else {
                    let _ = write!(cmd, " --serviceaccount={}", shell_escape(sa));
                }
            } else if let Some(u) = user {
                let _ = write!(cmd, " --user {}", shell_escape(u));
            } else if let Some(g) = group {
                let _ = write!(cmd, " --group {}", shell_escape(g));
            }
        }

        if dry_run {
            let out_fmt = output.unwrap_or("yaml");
            let _ = write!(cmd, " --dry-run=client -o {}", shell_escape(out_fmt));
        }

        cmd.push_str(&kubectl_context_flag(context));
        cmd
    }

    /// Build a `kubectl auth reconcile -f <manifest>` command.
    ///
    /// Same branch logic as `build_apply_command`: file path if starts with `/`, `./`, `~`;
    /// else inline via `echo ... | kubectl auth reconcile -f -`.
    #[must_use]
    pub fn build_auth_reconcile_command(
        kubectl_bin: Option<&str>,
        manifest: &str,
        dry_run: bool,
        remove_extra_permissions: bool,
        remove_extra_subjects: bool,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let is_file =
            manifest.starts_with('/') || manifest.starts_with("./") || manifest.starts_with('~');
        let mut cmd = if is_file {
            format!("{prefix}auth reconcile -f {}", shell_escape(manifest))
        } else {
            format!(
                "echo {} | {prefix}auth reconcile -f -",
                shell_escape(manifest)
            )
        };
        if dry_run {
            cmd.push_str(" --dry-run=client");
        }
        if remove_extra_permissions {
            cmd.push_str(" --remove-extra-permissions");
        }
        if remove_extra_subjects {
            cmd.push_str(" --remove-extra-subjects");
        }
        cmd.push_str(&kubectl_context_flag(context));
        cmd
    }

    /// Build a composite POSIX pipeline that reverse-scans RBAC bindings
    /// to find all principals that can perform `verb` on `resource`.
    ///
    /// Enumerates all `rolebindings` and `clusterrolebindings`, then for each
    /// binding resolves the referenced `Role`/`ClusterRole` and checks whether
    /// its rules cover the requested verb and resource (or `*`).
    ///
    /// The final stage emits a JSON array of objects with fields
    /// `namespace`, `kind`, `name`, `roleRefKind`, `roleRefName`.
    /// Requires `jq` on the remote host (exits with status 3 if missing).
    #[must_use]
    pub fn build_who_can_command(
        kubectl_bin: Option<&str>,
        verb: &str,
        resource: &str,
        namespace: Option<&str>,
        all_namespaces: bool,
        context: Option<&str>,
    ) -> String {
        let k_val = if let Some(bin) = kubectl_bin {
            if is_valid_binary_path(bin) {
                format!("K={bin}")
            } else {
                r#"K="$(if command -v kubectl >/dev/null 2>&1; then echo kubectl; elif command -v k3s >/dev/null 2>&1; then echo 'k3s kubectl'; elif command -v microk8s >/dev/null 2>&1; then echo 'microk8s kubectl'; else echo kubectl; fi)""#.to_string()
            }
        } else {
            r#"K="$(if command -v kubectl >/dev/null 2>&1; then echo kubectl; elif command -v k3s >/dev/null 2>&1; then echo 'k3s kubectl'; elif command -v microk8s >/dev/null 2>&1; then echo 'microk8s kubectl'; else echo kubectl; fi)""#.to_string()
        };

        let ctx_flag = kubectl_context_flag(context);
        let ctx_flag_trimmed = ctx_flag.trim();
        let v_esc = shell_escape(verb);
        let r_esc = shell_escape(resource);

        let scope = if all_namespaces {
            " -A".to_string()
        } else if let Some(ns) = namespace {
            format!(" -n {}", shell_escape(ns))
        } else {
            String::new()
        };

        format!(
            r#"{k_val}; command -v jq >/dev/null 2>&1 || {{ echo 'jq not installed on host (required for who_can JSON output)' >&2; exit 3; }}; CTX="{ctx_flag_trimmed}"; V={v_esc}; R={r_esc}; SCOPE='{scope}'; MATCHES=''; for B in $($K get rolebindings,clusterrolebindings$SCOPE $CTX -o jsonpath='{{range .items[*]}}{{.metadata.namespace}}{{"|"}}{{.kind}}{{"|"}}{{.metadata.name}}{{"|"}}{{.roleRef.kind}}{{"|"}}{{.roleRef.name}}{{"\n"}}{{end}}' 2>/dev/null); do RNS=$(printf %s "$B"|cut -d'|' -f1); RKIND=$(printf %s "$B"|cut -d'|' -f4); RNAME=$(printf %s "$B"|cut -d'|' -f5); if [ "$RKIND" = ClusterRole ]; then RULES=$($K get clusterrole "$RNAME" $CTX -o jsonpath='{{.rules[*]}}' 2>/dev/null); else RULES=$($K get role "$RNAME" ${{RNS:+-n "$RNS"}} $CTX -o jsonpath='{{.rules[*]}}' 2>/dev/null); fi; if printf %s "$RULES" | grep -q -e "$V" -e '\*' && printf %s "$RULES" | grep -q -e "$R" -e '\*'; then MATCHES="${{MATCHES}}$B"$'\n'; fi; done; printf '%s' "$MATCHES" | awk -F'|' 'NF==5 {{printf "{{\"namespace\":%s,\"kind\":%s,\"name\":%s,\"roleRefKind\":%s,\"roleRefName\":%s}}\n", (length($1)?"\""$1"\"":"null"), "\""$2"\"", "\""$3"\"", "\""$4"\"", "\""$5"\""}}' | jq -s '.'"#
        )
    }

    /// Build a composite POSIX pipeline that diagnoses RBAC for a service account.
    ///
    /// Emits a single JSON object with fields:
    /// - `serviceaccount`: `"ns:name"` identity string
    /// - `can_i_list`: array of strings from `kubectl auth can-i --list`
    /// - `granting_bindings`: array of `{namespace,kind,name,roleRefKind,roleRefName}` objects
    ///
    /// Requires `jq` on the remote host (exits with status 3 if missing).
    #[must_use]
    pub fn build_rbac_diagnose_command(
        kubectl_bin: Option<&str>,
        service_account: &str,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let k_val = if let Some(bin) = kubectl_bin {
            if is_valid_binary_path(bin) {
                format!("K={bin}")
            } else {
                r#"K="$(if command -v kubectl >/dev/null 2>&1; then echo kubectl; elif command -v k3s >/dev/null 2>&1; then echo 'k3s kubectl'; elif command -v microk8s >/dev/null 2>&1; then echo 'microk8s kubectl'; else echo kubectl; fi)""#.to_string()
            }
        } else {
            r#"K="$(if command -v kubectl >/dev/null 2>&1; then echo kubectl; elif command -v k3s >/dev/null 2>&1; then echo 'k3s kubectl'; elif command -v microk8s >/dev/null 2>&1; then echo 'microk8s kubectl'; else echo kubectl; fi)""#.to_string()
        };

        let ctx_flag = kubectl_context_flag(context);
        let ctx_flag_trimmed = ctx_flag.trim();
        let sa_esc = shell_escape(service_account);
        let ns_val = namespace.unwrap_or("default");
        let ns_esc = shell_escape(ns_val);

        format!(
            r#"{k_val}; command -v jq >/dev/null 2>&1 || {{ echo 'jq not installed on host (required for rbac_diagnose JSON output)' >&2; exit 3; }}; CTX="{ctx_flag_trimmed}"; SA={sa_esc}; NS={ns_esc}; AS="system:serviceaccount:$NS:$SA"; CANI=$($K auth can-i --list --as "$AS" -n "$NS" $CTX 2>/dev/null | tail -n +2); BINDINGS=$($K get rolebindings,clusterrolebindings --all-namespaces $CTX -o jsonpath='{{range .items[*]}}{{.metadata.namespace}}{{"|"}}{{.kind}}{{"|"}}{{.metadata.name}}{{"|"}}{{.roleRef.kind}}{{"|"}}{{.roleRef.name}}{{"|"}}{{range .subjects[*]}}{{.kind}}{{"/"}}{{.namespace}}{{"/"}}{{.name}}{{","}}{{end}}{{"\n"}}{{end}}' 2>/dev/null | grep -i "$SA" | grep -i "$NS"); CANI_JSON=$(printf '%s\n' "$CANI" | jq -Rs '[split("\n")[] | select(length > 0)]'); BIND_JSON=$(printf '%s\n' "$BINDINGS" | awk -F'|' 'NF>=5 {{printf "{{\"namespace\":%s,\"kind\":%s,\"name\":%s,\"roleRefKind\":%s,\"roleRefName\":%s}}\n", (length($1)?"\""$1"\"":"null"), "\""$2"\"", "\""$3"\"", "\""$4"\"", "\""$5"\""}}' | jq -s '.'); jq -n --arg sa "$AS" --argjson cani "${{CANI_JSON:-[]}}" --argjson bindings "${{BIND_JSON:-[]}}" '{{"serviceaccount":$sa,"can_i_list":$cani,"granting_bindings":$bindings}}'"#
        )
    }

    /// Build a composite POSIX pipeline that assembles a kubeconfig for a service account.
    ///
    /// Retrieves the cluster CA and creates a short-lived token, then prints
    /// a kubeconfig YAML that can be used directly with `KUBECONFIG=<file>`.
    #[must_use]
    pub fn build_kubeconfig_generate_command(
        kubectl_bin: Option<&str>,
        service_account: &str,
        namespace: Option<&str>,
        server_url: Option<&str>,
        cluster_name: Option<&str>,
        duration: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let prefix = kubectl_detect_prefix(kubectl_bin);
        let p = prefix.trim_end();

        let ctx_flag = kubectl_context_flag(context);
        let ctx_flag_trimmed = ctx_flag.trim();

        let sa_esc = shell_escape(service_account);
        let ns_val = namespace.unwrap_or("default");
        let ns_esc = shell_escape(ns_val);
        let cn_esc = shell_escape(cluster_name.unwrap_or("gen-cluster"));

        let srv_line = if let Some(url) = server_url {
            shell_escape(url)
        } else {
            format!(
                r"$({p} config view --minify -o jsonpath='{{.clusters[0].cluster.server}}' {ctx_flag_trimmed})"
            )
        };

        let dur_flag = if let Some(d) = duration {
            format!(" --duration {}", shell_escape(d))
        } else {
            String::new()
        };

        format!(
            r#"SA={sa_esc}; NS={ns_esc}; CN={cn_esc}; SRV={srv_line}; CA=$({p} config view --minify --raw -o jsonpath='{{.clusters[0].cluster.certificate-authority-data}}' {ctx_flag_trimmed}); TOKEN=$({p} create token "$SA" -n "$NS"{dur_flag} {ctx_flag_trimmed}); printf 'apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    certificate-authority-data: %s\n    server: %s\n  name: %s\ncontexts:\n- context:\n    cluster: %s\n    namespace: %s\n    user: %s\n  name: %s-%s\ncurrent-context: %s-%s\nusers:\n- name: %s\n  user:\n    token: %s\n' "$CA" "$SRV" "$CN" "$CN" "$NS" "$SA" "$CN" "$SA" "$CN" "$SA" "$SA" "$TOKEN""#
        )
    }
}

/// Builds helm CLI commands for remote execution.
pub struct HelmCommandBuilder;

impl HelmCommandBuilder {
    /// Build a `helm list` command.
    ///
    /// Constructs: `{helm} list [-n {ns}] [-A] [-a] [--filter {f}]
    /// [-o {output}] [--failed] [--pending] [-l {selector}] [--max {max}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::fn_params_excessive_bools)]
    pub fn build_list_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        namespace: Option<&str>,
        all_namespaces: bool,
        all: bool,
        filter: Option<&str>,
        output: Option<&str>,
        failed: bool,
        pending: bool,
        selector: Option<&str>,
        max: Option<u64>,
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

        if failed {
            cmd.push_str(" --failed");
        }

        if pending {
            cmd.push_str(" --pending");
        }

        if let Some(sel) = selector {
            let _ = write!(cmd, " -l {}", shell_escape(sel));
        }

        if let Some(m) = max {
            let _ = write!(cmd, " --max {m}");
        }

        cmd
    }

    /// Build a `helm status` command.
    ///
    /// Constructs: `{helm} status {release} [-n {ns}] [-o {output}]
    /// [--revision {N}] [--show-resources] [--show-desc]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_status_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        namespace: Option<&str>,
        output: Option<&str>,
        revision: Option<u64>,
        show_resources: bool,
        show_desc: bool,
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

        if show_resources {
            cmd.push_str(" --show-resources");
        }

        if show_desc {
            cmd.push_str(" --show-desc");
        }

        cmd
    }

    /// Build a `helm get` command (read-only inspection of a release).
    ///
    /// `subcommand` is validated by the caller
    /// (`KubernetesCommandBuilder::validate_helm_get_subcommand`).
    ///
    /// Constructs: `[KUBECONFIG=…] {helm} get {subcommand} {release}
    /// [-n {ns}] [--revision {N}] [-o {output}]`
    #[must_use]
    pub fn build_get_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        subcommand: &str,
        release: &str,
        namespace: Option<&str>,
        revision: Option<u64>,
        output: Option<&str>,
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
        if let Some(out) = output {
            let _ = write!(cmd, " -o {}", shell_escape(out));
        }
        cmd
    }

    /// Build a `helm upgrade` command.
    ///
    /// Constructs: `{helm} upgrade {release} {chart} [-n {ns}]
    /// [--set k=v ...] [-f values.yaml ...] [--dry-run={mode}]
    /// [--wait] [--timeout {t}] [--install] [--version {v}]
    /// [--create-namespace] [--atomic] [--reuse-values]
    /// [--set-string k=v ...] [--wait-for-jobs]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::fn_params_excessive_bools)]
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
        atomic: bool,
        reuse_values: bool,
        set_string: Option<&HashMap<String, String>>,
        wait_for_jobs: bool,
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

        if atomic {
            cmd.push_str(" --atomic");
        }

        if reuse_values {
            cmd.push_str(" --reuse-values");
        }

        if let Some(ss) = set_string {
            let mut keys: Vec<&String> = ss.keys().collect();
            keys.sort();
            for key in keys {
                let val = &ss[key];
                let _ = write!(
                    cmd,
                    " --set-string {}={}",
                    shell_escape(key),
                    shell_escape(val)
                );
            }
        }

        if wait_for_jobs {
            cmd.push_str(" --wait-for-jobs");
        }

        cmd
    }

    /// Build a `helm install` command.
    ///
    /// Constructs: `{helm} install {release} {chart} [-n {ns}]
    /// [--set k=v ...] [-f values.yaml ...] [--dry-run={mode}]
    /// [--wait] [--create-namespace] [--version {v}]
    /// [--atomic] [--set-string k=v ...] [--wait-for-jobs] [--timeout {t}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::fn_params_excessive_bools)]
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
        atomic: bool,
        set_string: Option<&HashMap<String, String>>,
        wait_for_jobs: bool,
        timeout: Option<&str>,
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

        if atomic {
            cmd.push_str(" --atomic");
        }

        if let Some(ss) = set_string {
            let mut keys: Vec<&String> = ss.keys().collect();
            keys.sort();
            for key in keys {
                let val = &ss[key];
                let _ = write!(
                    cmd,
                    " --set-string {}={}",
                    shell_escape(key),
                    shell_escape(val)
                );
            }
        }

        if wait_for_jobs {
            cmd.push_str(" --wait-for-jobs");
        }

        if let Some(t) = timeout {
            let _ = write!(cmd, " --timeout {}", shell_escape(t));
        }

        cmd
    }

    /// Build a `helm rollback` command.
    ///
    /// Constructs: `{helm} rollback {release} [{revision}] [-n {ns}]
    /// [--dry-run={mode}] [--wait] [--cleanup-on-fail] [--wait-for-jobs]
    /// [--timeout {t}] [--force]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::fn_params_excessive_bools)]
    pub fn build_rollback_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        revision: Option<u64>,
        namespace: Option<&str>,
        dry_run: Option<&str>,
        wait: bool,
        cleanup_on_fail: bool,
        wait_for_jobs: bool,
        timeout: Option<&str>,
        force: bool,
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

        if cleanup_on_fail {
            cmd.push_str(" --cleanup-on-fail");
        }

        if wait_for_jobs {
            cmd.push_str(" --wait-for-jobs");
        }

        if let Some(t) = timeout {
            let _ = write!(cmd, " --timeout {}", shell_escape(t));
        }

        if force {
            cmd.push_str(" --force");
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
    /// [--keep-history] [--no-hooks] [--wait] [--cascade {mode}]
    /// [--timeout {t}]`
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::fn_params_excessive_bools)]
    pub fn build_uninstall_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        namespace: Option<&str>,
        dry_run: bool,
        keep_history: bool,
        no_hooks: bool,
        wait: bool,
        cascade: Option<&str>,
        timeout: Option<&str>,
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

        if no_hooks {
            cmd.push_str(" --no-hooks");
        }

        if wait {
            cmd.push_str(" --wait");
        }

        if let Some(c) = cascade {
            let _ = write!(cmd, " --cascade {}", shell_escape(c));
        }

        if let Some(t) = timeout {
            let _ = write!(cmd, " --timeout {}", shell_escape(t));
        }

        cmd
    }

    /// Build a `helm template` command (client-side render, read-only).
    ///
    /// Constructs: `[KUBECONFIG=…] {helm} template {release} {chart}
    /// [-n {ns}] [--set k=v …] [-f values.yaml …] [--version {v}]
    /// [--show-only {tpl} …] [--include-crds] [--kube-version {v}]
    /// [--api-versions {v} …] [--validate]`
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
        include_crds: bool,
        kube_version: Option<&str>,
        api_versions: Option<&[String]>,
        validate: bool,
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
        if include_crds {
            cmd.push_str(" --include-crds");
        }
        if let Some(kv) = kube_version {
            let _ = write!(cmd, " --kube-version {}", shell_escape(kv));
        }
        if let Some(avs) = api_versions {
            for av in avs {
                let _ = write!(cmd, " --api-versions {}", shell_escape(av));
            }
        }
        if validate {
            cmd.push_str(" --validate");
        }
        cmd
    }

    /// Validate a Helm repository name.
    pub fn validate_repo_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "repo name must not be empty".into(),
            });
        }
        if name.starts_with('-') {
            return Err(BridgeError::CommandDenied {
                reason: format!("repo name must not start with '-': '{name}'"),
            });
        }
        if name.len() > 253 {
            return Err(BridgeError::CommandDenied {
                reason: format!("repo name exceeds 253 characters: '{name}'"),
            });
        }
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(BridgeError::CommandDenied {
                reason: format!("repo name contains invalid characters: '{name}'"),
            });
        }
        Ok(())
    }

    /// Validate a Helm repository URL.
    pub fn validate_repo_url(url: &str) -> Result<()> {
        if url.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "repo URL must not be empty".into(),
            });
        }
        if url.starts_with('-') {
            return Err(BridgeError::CommandDenied {
                reason: format!("repo URL must not start with '-': '{url}'"),
            });
        }
        if !url.starts_with("https://") && !url.starts_with("http://") && !url.starts_with("oci://")
        {
            return Err(BridgeError::CommandDenied {
                reason: format!("repo URL must start with https://, http://, or oci://: '{url}'"),
            });
        }
        if url.chars().any(char::is_whitespace) {
            return Err(BridgeError::CommandDenied {
                reason: format!("repo URL must not contain whitespace: '{url}'"),
            });
        }
        if url
            .chars()
            .any(|c| matches!(c, ';' | '|' | '&' | '$' | '`' | '<' | '>'))
        {
            return Err(BridgeError::CommandDenied {
                reason: format!("repo URL contains shell meta-characters: '{url}'"),
            });
        }
        Ok(())
    }

    /// Validate a `helm uninstall --cascade` value.
    ///
    /// Allowed values: `background`, `orphan`, `foreground`.
    pub fn validate_cascade(cascade: &str) -> Result<()> {
        if cascade.starts_with('-') || !["background", "orphan", "foreground"].contains(&cascade) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "invalid cascade value: '{cascade}' (expected: background, orphan, foreground)"
                ),
            });
        }
        Ok(())
    }

    /// Validate a Helm output format.
    pub fn validate_helm_output(output: &str) -> Result<()> {
        if output.starts_with('-') || !["table", "json", "yaml"].contains(&output) {
            return Err(BridgeError::CommandDenied {
                reason: format!("invalid output format: '{output}' (expected: table, json, yaml)"),
            });
        }
        Ok(())
    }

    /// Validate a `helm show` subcommand.
    pub fn validate_show_subcommand(sub: &str) -> Result<()> {
        if !["all", "chart", "readme", "values", "crds"].contains(&sub) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "invalid show subcommand: '{sub}' (expected: all, chart, readme, values, crds)"
                ),
            });
        }
        Ok(())
    }

    /// Validate a `helm dependency` subcommand.
    pub fn validate_dependency_subcommand(sub: &str) -> Result<()> {
        if !["build", "update", "list"].contains(&sub) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "invalid dependency subcommand: '{sub}' (expected: build, update, list)"
                ),
            });
        }
        Ok(())
    }

    /// Validate a `helm diff` subcommand (requires helm-diff plugin).
    pub fn validate_diff_subcommand(sub: &str) -> Result<()> {
        if !["upgrade", "rollback", "release", "revision"].contains(&sub) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "invalid diff subcommand: '{sub}' (expected: upgrade, rollback, release, revision)"
                ),
            });
        }
        Ok(())
    }

    /// Build a `helm repo add` command.
    #[must_use]
    pub fn build_repo_add_command(
        helm_bin: Option<&str>,
        name: &str,
        url: &str,
        username: Option<&str>,
        password: Option<&str>,
        force_update: bool,
        pass_credentials: bool,
    ) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!(
            "{prefix}repo add {} {}",
            shell_escape(name),
            shell_escape(url)
        );
        if let Some(u) = username {
            let _ = write!(cmd, " --username {}", shell_escape(u));
        }
        if let Some(p) = password {
            let _ = write!(cmd, " --password {}", shell_escape(p));
        }
        if force_update {
            cmd.push_str(" --force-update");
        }
        if pass_credentials {
            cmd.push_str(" --pass-credentials");
        }
        cmd
    }

    /// Build a `helm repo update` command.
    #[must_use]
    pub fn build_repo_update_command(helm_bin: Option<&str>, repos: Option<&[String]>) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!("{prefix}repo update");
        if let Some(repos) = repos {
            for r in repos {
                let _ = write!(cmd, " {}", shell_escape(r));
            }
        }
        cmd
    }

    /// Build a `helm repo list` command.
    #[must_use]
    pub fn build_repo_list_command(helm_bin: Option<&str>, output: Option<&str>) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!("{prefix}repo list");
        if let Some(out) = output {
            let _ = write!(cmd, " -o {}", shell_escape(out));
        }
        cmd
    }

    /// Build a `helm repo remove` command.
    pub fn build_repo_remove_command(helm_bin: Option<&str>, names: &[String]) -> Result<String> {
        if names.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "at least one repo name is required for repo remove".into(),
            });
        }
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!("{prefix}repo remove");
        for name in names {
            let _ = write!(cmd, " {}", shell_escape(name));
        }
        Ok(cmd)
    }

    /// Build a `helm show` command.
    #[must_use]
    pub fn build_show_command(
        helm_bin: Option<&str>,
        subcommand: &str,
        chart: &str,
        version: Option<&str>,
        repo: Option<&str>,
        devel: bool,
    ) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!(
            "{prefix}show {} {}",
            shell_escape(subcommand),
            shell_escape(chart)
        );
        if let Some(v) = version {
            let _ = write!(cmd, " --version {}", shell_escape(v));
        }
        if let Some(r) = repo {
            let _ = write!(cmd, " --repo {}", shell_escape(r));
        }
        if devel {
            cmd.push_str(" --devel");
        }
        cmd
    }

    /// Build a `helm pull` command.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_pull_command(
        helm_bin: Option<&str>,
        chart: &str,
        version: Option<&str>,
        repo: Option<&str>,
        untar: bool,
        destination: Option<&str>,
        devel: bool,
        verify: bool,
    ) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!("{prefix}pull {}", shell_escape(chart));
        if let Some(v) = version {
            let _ = write!(cmd, " --version {}", shell_escape(v));
        }
        if let Some(r) = repo {
            let _ = write!(cmd, " --repo {}", shell_escape(r));
        }
        if untar {
            cmd.push_str(" --untar");
        }
        if let Some(d) = destination {
            let _ = write!(cmd, " --destination {}", shell_escape(d));
        }
        if devel {
            cmd.push_str(" --devel");
        }
        if verify {
            cmd.push_str(" --verify");
        }
        cmd
    }

    /// Build a `helm lint` command.
    #[must_use]
    pub fn build_lint_command(
        helm_bin: Option<&str>,
        chart_path: &str,
        strict: bool,
        values_files: Option<&[String]>,
        set_values: Option<&HashMap<String, String>>,
        quiet: bool,
    ) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!("{prefix}lint {}", shell_escape(chart_path));
        if strict {
            cmd.push_str(" --strict");
        }
        if let Some(files) = values_files {
            for file in files {
                let _ = write!(cmd, " -f {}", shell_escape(file));
            }
        }
        if let Some(vals) = set_values {
            let mut keys: Vec<&String> = vals.keys().collect();
            keys.sort();
            for key in keys {
                let val = &vals[key];
                let _ = write!(cmd, " --set {}={}", shell_escape(key), shell_escape(val));
            }
        }
        if quiet {
            cmd.push_str(" --quiet");
        }
        cmd
    }

    /// Build a `helm dependency` command.
    #[must_use]
    pub fn build_dependency_command(
        helm_bin: Option<&str>,
        subcommand: &str,
        chart_path: &str,
        skip_refresh: bool,
        verify: bool,
    ) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!(
            "{prefix}dependency {} {}",
            shell_escape(subcommand),
            shell_escape(chart_path)
        );
        if skip_refresh {
            cmd.push_str(" --skip-refresh");
        }
        if verify {
            cmd.push_str(" --verify");
        }
        cmd
    }

    /// Build a `helm diff` command (requires helm-diff plugin).
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_diff_command(
        helm_bin: Option<&str>,
        subcommand: &str,
        release: &str,
        chart: Option<&str>,
        namespace: Option<&str>,
        values_files: Option<&[String]>,
        set_values: Option<&HashMap<String, String>>,
        version: Option<&str>,
        detailed_exitcode: bool,
    ) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        let guard = format!(
            "{prefix}plugin list | grep -q diff || {{ echo 'helm-diff plugin not installed' >&2; exit 4; }}; "
        );
        let escaped_sub = shell_escape(subcommand);
        let escaped_release = shell_escape(release);
        let mut cmd = format!("{guard}{prefix}diff {escaped_sub} {escaped_release}");
        if let Some(c) = chart {
            let _ = write!(cmd, " {}", shell_escape(c));
        }
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if let Some(files) = values_files {
            for file in files {
                let _ = write!(cmd, " -f {}", shell_escape(file));
            }
        }
        if let Some(vals) = set_values {
            let mut keys: Vec<&String> = vals.keys().collect();
            keys.sort();
            for key in keys {
                let val = &vals[key];
                let _ = write!(cmd, " --set {}={}", shell_escape(key), shell_escape(val));
            }
        }
        if let Some(v) = version {
            let _ = write!(cmd, " --version {}", shell_escape(v));
        }
        if detailed_exitcode {
            cmd.push_str(" --detailed-exitcode");
        }
        cmd
    }

    /// Build a `helm test` command.
    #[must_use]
    pub fn build_test_command(
        helm_bin: Option<&str>,
        kubeconfig: Option<&str>,
        release: &str,
        namespace: Option<&str>,
        logs: bool,
        timeout: Option<&str>,
        filter: Option<&str>,
    ) -> String {
        let kube_env = kubeconfig_env_prefix(kubeconfig);
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!("{kube_env}{prefix}test {}", shell_escape(release));
        if let Some(ns) = namespace {
            let _ = write!(cmd, " -n {}", shell_escape(ns));
        }
        if logs {
            cmd.push_str(" --logs");
        }
        if let Some(t) = timeout {
            let _ = write!(cmd, " --timeout {}", shell_escape(t));
        }
        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }
        cmd
    }

    /// Build a `helm search repo` command.
    #[must_use]
    pub fn build_search_repo_command(
        helm_bin: Option<&str>,
        keyword: &str,
        version: Option<&str>,
        versions: bool,
        devel: bool,
        output: Option<&str>,
        regexp: bool,
    ) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        let mut cmd = format!("{prefix}search repo {}", shell_escape(keyword));
        if let Some(v) = version {
            let _ = write!(cmd, " --version {}", shell_escape(v));
        }
        if versions {
            cmd.push_str(" --versions");
        }
        if devel {
            cmd.push_str(" --devel");
        }
        if let Some(out) = output {
            let _ = write!(cmd, " -o {}", shell_escape(out));
        }
        if regexp {
            cmd.push_str(" --regexp");
        }
        cmd
    }

    /// Build a `helm plugin list` command.
    #[must_use]
    pub fn build_plugin_list_command(helm_bin: Option<&str>) -> String {
        let prefix = helm_detect_prefix(helm_bin);
        format!("{prefix}plugin list")
    }
}

// ============================================================
// Wave-9a: Networking validators (shared across the 6 net tools)
// ============================================================

/// Validate a TCP port number (1–65535; 0 is rejected).
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if `port` is 0.
pub fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(BridgeError::CommandDenied {
            reason: "port must be in range 1–65535 (got 0)".to_string(),
        });
    }
    Ok(())
}

/// Validate an HTTP probe/proxy path.
///
/// The path must start with `/`, allow URL-safe characters
/// `[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]`, and must not contain
/// newline, space, backtick, or `$(` (shell injection guards).
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the path is invalid.
pub fn validate_probe_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "probe path must not be empty".to_string(),
        });
    }
    if !path.starts_with('/') {
        return Err(BridgeError::CommandDenied {
            reason: format!("probe path must start with '/': {path}"),
        });
    }
    // Explicit rejection of shell-injection characters
    for ch in path.chars() {
        if matches!(ch, '\n' | '\r' | ' ' | '`') {
            return Err(BridgeError::CommandDenied {
                reason: format!("probe path contains disallowed character '{ch}': {path}"),
            });
        }
    }
    if path.contains("$(") {
        return Err(BridgeError::CommandDenied {
            reason: format!("probe path contains shell substitution: {path}"),
        });
    }
    // Check for path traversal segments
    for segment in path.split('/') {
        if segment == ".." {
            return Err(BridgeError::CommandDenied {
                reason: format!("probe path contains path traversal: {path}"),
            });
        }
    }
    // Validate charset — URL-safe + reserved chars
    for ch in path.chars() {
        if !matches!(ch,
            'A'..='Z' | 'a'..='z' | '0'..='9'
            | '.' | '_' | '~' | ':' | '/' | '?' | '#' | '@'
            | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+'
            | ',' | ';' | '=' | '%' | '-')
        {
            return Err(BridgeError::CommandDenied {
                reason: format!("probe path contains disallowed character '{ch}': {path}"),
            });
        }
    }
    Ok(())
}

/// Validate a DNS name / service name (RFC 1123 label rules).
///
/// Rules: non-empty, ≤253 chars, chars `[a-z0-9.-]`, starts and ends
/// with alphanumeric, no leading `-`.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the name is invalid.
pub fn validate_dns_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "DNS name must not be empty".to_string(),
        });
    }
    if name.len() > 253 {
        return Err(BridgeError::CommandDenied {
            reason: format!("DNS name exceeds 253 chars: {name}"),
        });
    }
    if name.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("DNS name must not start with '-': {name}"),
        });
    }
    if !name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("DNS name must start with alphanumeric: {name}"),
        });
    }
    if !name
        .chars()
        .last()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("DNS name must end with alphanumeric: {name}"),
        });
    }
    for ch in name.chars() {
        if !matches!(ch, 'a'..='z' | '0'..='9' | '.' | '-') {
            return Err(BridgeError::CommandDenied {
                reason: format!("DNS name contains disallowed character '{ch}': {name}"),
            });
        }
    }
    Ok(())
}

/// Validate an ephemeral probe pod image reference.
///
/// Allowed chars: `[A-Za-z0-9._/:@-]`. Must be non-empty and must not
/// start with `-`.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the image is invalid.
pub fn validate_probe_image(img: &str) -> Result<()> {
    if img.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "probe image must not be empty".to_string(),
        });
    }
    if img.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("probe image must not start with '-': {img}"),
        });
    }
    for ch in img.chars() {
        if !matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '/' | ':' | '@' | '-') {
            return Err(BridgeError::CommandDenied {
                reason: format!("probe image contains disallowed character '{ch}': {img}"),
            });
        }
    }
    Ok(())
}

/// Validate a bounded sleep/wait duration in seconds.
///
/// Reject 0 and values above 300 (5 minutes).
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if `secs` is 0 or > 300.
pub fn validate_duration_secs(secs: u64) -> Result<()> {
    if secs == 0 {
        return Err(BridgeError::CommandDenied {
            reason: "wait duration must be at least 1 second".to_string(),
        });
    }
    if secs > 300 {
        return Err(BridgeError::CommandDenied {
            reason: format!("wait duration exceeds 300 s cap (got {secs})"),
        });
    }
    Ok(())
}

/// Validate the proxy resource type for `kubectl get --raw`.
///
/// Only `services` and `pods` are accepted (the common Kubernetes API
/// proxy paths).
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] for any other value.
pub fn validate_proxy_resource(resource: &str) -> Result<()> {
    match resource {
        "services" | "pods" => Ok(()),
        _ => Err(BridgeError::CommandDenied {
            reason: format!("proxy resource must be 'services' or 'pods', got '{resource}'"),
        }),
    }
}

// ============================================================
// Wave-9a: Networking command builders (KubernetesCommandBuilder impl)
// ============================================================

impl KubernetesCommandBuilder {
    /// Build a **bounded** port-forward run-and-probe command.
    ///
    /// Starts `kubectl port-forward` in the background, waits `wait_secs`,
    /// optionally probes via `curl`, then unconditionally kills the
    /// background process and cleans up the tmp log file.
    ///
    /// # Parameters
    ///
    /// * `kubectl_bin` — Optional explicit kubectl binary path.
    /// * `target` — Resource target, e.g. `svc/myapp` or `pod/mypod-xyz`.
    /// * `ports` — Port mapping string, e.g. `8080:80` or `9090`.
    /// * `probe_path` — Optional HTTP path to curl after the forward is up, e.g. `/healthz`.
    /// * `wait_secs` — Bounded sleep window (1–30 s).
    /// * `namespace` — Optional Kubernetes namespace.
    /// * `address` — Optional `--address` bind address (default 127.0.0.1).
    /// * `context` — Optional kubeconfig context.
    ///
    /// # Errors
    ///
    /// Returns an error if namespace, context, `probe_path`, `wait_secs`, or
    /// port extraction fails validation.
    #[allow(clippy::too_many_arguments)]
    pub fn build_port_forward_command(
        kubectl_bin: Option<&str>,
        target: &str,
        ports: &str,
        probe_path: Option<&str>,
        wait_secs: u64,
        namespace: Option<&str>,
        address: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        if let Some(pp) = probe_path {
            validate_probe_path(pp)?;
        }
        // wait_secs bounded to 1–30 for port-forward (tighter than the 300 s global cap)
        if wait_secs == 0 || wait_secs > 30 {
            return Err(BridgeError::CommandDenied {
                reason: format!("port-forward wait_secs must be 1–30 (got {wait_secs})"),
            });
        }

        // Extract the local port from "local:remote" or bare "port"
        let local_port = ports.split(':').next().unwrap_or(ports).trim();
        // Validate it is a valid port number
        let local_port_num: u16 = local_port.parse().map_err(|_| BridgeError::CommandDenied {
            reason: format!("invalid local port in mapping '{ports}'"),
        })?;
        validate_port(local_port_num)?;
        // Validate remote port if present
        if let Some(remote_raw) = ports.split(':').nth(1) {
            let remote_num: u16 =
                remote_raw
                    .trim()
                    .parse()
                    .map_err(|_| BridgeError::CommandDenied {
                        reason: format!("invalid remote port in mapping '{ports}'"),
                    })?;
            validate_port(remote_num)?;
        }

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_flag = namespace
            .map(|ns| format!(" -n {}", shell_escape(ns)))
            .unwrap_or_default();
        let addr_flag = address
            .map(|a| format!(" --address {}", shell_escape(a)))
            .unwrap_or_default();
        let ports_esc = shell_escape(ports);
        let target_esc = shell_escape(target);
        let wait_esc = shell_escape(&wait_secs.to_string());

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "{prefix}port-forward {target_esc} {ports_esc}{ns_flag}{addr_flag}{ctx_flag} \
             >/tmp/pf.$$ 2>&1 & PF=$!; \
             sleep {wait_esc}; \
             if kill -0 $PF 2>/dev/null; then \
               echo '=== port-forward UP ==='; cat /tmp/pf.$$;"
        );
        if let Some(pp) = probe_path {
            let local_port_esc = shell_escape(local_port);
            let pp_esc = shell_escape(pp);
            let _ = write!(
                cmd,
                " echo '=== probe ==='; \
                 curl -sS -m 5 -o /dev/null -w 'HTTP %{{http_code}} in %{{time_total}}s\\n' \
                 'http://127.0.0.1:{local_port_esc}{pp_esc}' || echo 'probe FAILED';"
            );
        }
        let _ = write!(
            cmd,
            " else echo '=== port-forward DIED ==='; cat /tmp/pf.$$; fi; \
             kill $PF 2>/dev/null; wait $PF 2>/dev/null; rm -f /tmp/pf.$$"
        );
        Ok(cmd)
    }

    /// Build an endpoints inspection command — selector ↔ pod readiness JOIN.
    ///
    /// Returns a composite pipeline showing the service selector, pods
    /// matching that selector (with readiness), and the `EndpointSlice`
    /// ready/notReady addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if namespace, context, or service name validation fails.
    pub fn build_endpoints_command(
        kubectl_bin: Option<&str>,
        service: &str,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        validate_dns_name(service)?;

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_val = namespace.unwrap_or("default");
        let ns_esc = shell_escape(ns_val);
        let svc_esc = shell_escape(service);

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "K={prefix_esc}; NS={ns_esc}; \
             echo '=== Selector ==='; \
             $K get svc {svc_esc} -n $NS -o jsonpath='{{.spec.selector}}'{ctx_flag}; \
             echo; \
             echo '=== Pods matching selector (readiness) ==='; \
             SEL=$($K get svc {svc_esc} -n $NS \
               -o jsonpath='{{range $k,$v := .spec.selector}}{{$k}}={{$v}},{{end}}'{ctx_flag} \
               | sed 's/,$//'); \
             $K get pods -n $NS -l \"$SEL\" \
               -o custom-columns='POD:.metadata.name,READY:.status.containerStatuses[*].ready,\
IP:.status.podIP,PHASE:.status.phase'{ctx_flag}; \
             echo '=== EndpointSlice ready/notReady ==='; \
             $K get endpoints {svc_esc} -n $NS \
               -o custom-columns='READY:.subsets[*].addresses[*].ip,\
NOTREADY:.subsets[*].notReadyAddresses[*].ip,\
PORTS:.subsets[*].ports[*].port'{ctx_flag}",
            prefix_esc = shell_escape(prefix.trim_end()),
            ns_esc = ns_esc,
            svc_esc = svc_esc,
            ctx_flag = ctx_flag,
        );
        Ok(cmd)
    }

    /// Build an ingress describe command — host/path → backend svc:port + TLS + ADDRESS.
    ///
    /// Returns a composite pipeline showing the ingress overview, the
    /// host/path-to-backend mapping, and the endpoints of each backend
    /// service.
    ///
    /// # Errors
    ///
    /// Returns an error if namespace, context, or ingress name validation fails.
    pub fn build_ingress_describe_command(
        kubectl_bin: Option<&str>,
        ingress: &str,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        validate_dns_name(ingress)?;

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_val = namespace.unwrap_or("default");
        let ns_esc = shell_escape(ns_val);
        let ing_esc = shell_escape(ingress);

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "K={prefix_esc}; NS={ns_esc}; \
             echo '=== Ingress {ing_esc} ADDRESS/class ==='; \
             $K get ingress {ing_esc} -n $NS \
               -o custom-columns='NAME:.metadata.name,CLASS:.spec.ingressClassName,\
HOSTS:.spec.rules[*].host,ADDRESS:.status.loadBalancer.ingress[*].ip'{ctx_flag}; \
             echo '=== host/path -> backend svc:port ==='; \
             $K get ingress {ing_esc} -n $NS \
               -o jsonpath='{{range .spec.rules[*]}}{{.host}}{{\"\\n\"}}\
{{range .http.paths[*]}}  {{.path}} -> {{.backend.service.name}}:{{.backend.service.port.number}}{{\"\\n\"}}{{end}}{{end}}'{ctx_flag}; \
             echo; \
             echo '=== backend service endpoints ==='; \
             for s in $($K get ingress {ing_esc} -n $NS \
               -o jsonpath='{{.spec.rules[*].http.paths[*].backend.service.name}}'{ctx_flag}); do \
               echo \"-- $s --\"; \
               $K get endpoints $s -n $NS \
                 -o custom-columns='ADDRS:.subsets[*].addresses[*].ip,\
PORTS:.subsets[*].ports[*].port'{ctx_flag} 2>/dev/null || echo 'no endpoints'; \
             done",
            prefix_esc = shell_escape(prefix.trim_end()),
            ns_esc = ns_esc,
            ing_esc = ing_esc,
            ctx_flag = ctx_flag,
        );
        Ok(cmd)
    }

    /// Build a `NetworkPolicy` inspection command.
    ///
    /// Shows the policy YAML, matched pods (via `podSelector`), and a
    /// CNI enforcement caveat for flannel-based K3s clusters.
    ///
    /// # Errors
    ///
    /// Returns an error if namespace, context, or policy name validation fails.
    pub fn build_networkpolicy_command(
        kubectl_bin: Option<&str>,
        policy: &str,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        validate_dns_name(policy)?;

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_val = namespace.unwrap_or("default");
        let ns_esc = shell_escape(ns_val);
        let pol_esc = shell_escape(policy);

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "K={prefix_esc}; NS={ns_esc}; \
             echo '=== NetworkPolicy {pol_esc} ==='; \
             $K get networkpolicy {pol_esc} -n $NS -o yaml{ctx_flag}; \
             echo '=== podSelector -> matched pods ==='; \
             SEL=$($K get networkpolicy {pol_esc} -n $NS \
               -o jsonpath='{{range $k,$v := .spec.podSelector.matchLabels}}{{$k}}={{$v}},{{end}}'{ctx_flag} \
               | sed 's/,$//'); \
             if [ -n \"$SEL\" ]; then \
               $K get pods -n $NS -l \"$SEL\" \
                 -o custom-columns='POD:.metadata.name,IP:.status.podIP,PHASE:.status.phase'{ctx_flag}; \
             else \
               echo 'empty podSelector = selects ALL pods in namespace'; \
               $K get pods -n $NS \
                 -o custom-columns='POD:.metadata.name,IP:.status.podIP'{ctx_flag}; \
             fi; \
             echo '=== CNI enforcement caveat ==='; \
             if $K get pods -n kube-system -l app=flannel -o name{ctx_flag} 2>/dev/null | grep -q .; then \
               echo 'WARNING: flannel (default k3s CNI) does NOT enforce NetworkPolicy. \
Install Calico/Cilium or k3s --flannel-backend=none for enforcement.'; \
             else \
               echo 'flannel not detected -- verify your CNI supports NetworkPolicy enforcement.'; \
             fi",
            prefix_esc = shell_escape(prefix.trim_end()),
            ns_esc = ns_esc,
            pol_esc = pol_esc,
            ctx_flag = ctx_flag,
        );
        Ok(cmd)
    }

    /// Build a `kubectl get --raw` proxy-get command.
    ///
    /// Proxies an HTTP request through the Kubernetes API server to a
    /// service or pod.  The proxy path is validated to prevent injection.
    ///
    /// # Errors
    ///
    /// Returns an error if namespace, context, resource, name, proxy path,
    /// or port validation fails.
    pub fn build_proxy_get_command(
        kubectl_bin: Option<&str>,
        resource: &str,
        name: &str,
        proxy_path: &str,
        port: Option<u16>,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        validate_proxy_resource(resource)?;
        validate_dns_name(name)?;
        validate_probe_path(proxy_path)?;
        if let Some(p) = port {
            validate_port(p)?;
        }

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_val = namespace.unwrap_or("default");

        // Build the raw API path: /api/v1/namespaces/<ns>/<resource>/<name>[:<port>]/proxy<path>
        let port_suffix = port.map(|p| format!(":{p}")).unwrap_or_default();
        let raw_path =
            format!("/api/v1/namespaces/{ns_val}/{resource}/{name}{port_suffix}/proxy{proxy_path}");
        let raw_path_esc = shell_escape(&raw_path);

        let mut cmd = String::new();
        let _ = write!(cmd, "{prefix}get --raw {raw_path_esc}{ctx_flag}");
        Ok(cmd)
    }

    /// Build a `CoreDNS` health-check composite command.
    ///
    /// Shows `CoreDNS` pods, service, endpoints, Corefile, and optionally
    /// resolves a DNS name via a short-lived busybox pod.
    ///
    /// # Errors
    ///
    /// Returns an error if namespace, context, or resolve name validation fails.
    pub fn build_dns_check_command(
        kubectl_bin: Option<&str>,
        resolve_name: Option<&str>,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        if let Some(rn) = resolve_name {
            validate_dns_name(rn)?;
        }

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_flag = namespace
            .map(|ns| format!(" -n {}", shell_escape(ns)))
            .unwrap_or_default();

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "K={prefix_esc}; \
             echo '=== CoreDNS Pods ==='; \
             $K get pods -n kube-system -l k8s-app=kube-dns -o wide{ctx_flag}; \
             echo '=== CoreDNS Service + Endpoints ==='; \
             $K get svc,endpoints -n kube-system -l k8s-app=kube-dns{ctx_flag}; \
             echo '=== Corefile ==='; \
             $K get configmap coredns -n kube-system \
               -o jsonpath='{{.data.Corefile}}'{ctx_flag}; \
             echo",
            prefix_esc = shell_escape(prefix.trim_end()),
            ctx_flag = ctx_flag,
        );
        if let Some(rn) = resolve_name {
            let rn_esc = shell_escape(rn);
            let _ = write!(
                cmd,
                "; echo '=== Resolve {rn_esc} ==='; \
                 $K run dns-probe-$${ns_flag}{ctx_flag} \
                   --image=busybox:1.36 --restart=Never --command --attach --rm \
                   --timeout=20s -- nslookup {rn_esc}"
            );
        }
        Ok(cmd)
    }
}

// ============================================================
// Wave-9b: validate_abs_path (for addon_manifests)
// ============================================================

/// Validate an absolute filesystem path.
///
/// Rules: non-empty, must start with `/`, must not contain `..` segments,
/// charset `[A-Za-z0-9._/-]`.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the path is invalid.
pub fn validate_abs_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "path must not be empty".to_string(),
        });
    }
    if !path.starts_with('/') {
        return Err(BridgeError::CommandDenied {
            reason: format!("path must be absolute (start with '/'): {path}"),
        });
    }
    for segment in path.split('/') {
        if segment == ".." {
            return Err(BridgeError::CommandDenied {
                reason: format!("path contains path traversal '..': {path}"),
            });
        }
    }
    for ch in path.chars() {
        if !matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '/' | '-') {
            return Err(BridgeError::CommandDenied {
                reason: format!("path contains disallowed character '{ch}': {path}"),
            });
        }
    }
    Ok(())
}

// ============================================================
// Wave-9b: Networking command builders (6 new tools)
// ============================================================

impl KubernetesCommandBuilder {
    /// Build a comprehensive service describe command.
    ///
    /// Shows service overview, spec (type/clusterIP/ports/selector),
    /// endpoints (ready addresses), and klipper svclb pods for K3s
    /// `LoadBalancer` services.
    ///
    /// # Errors
    ///
    /// Returns an error if namespace, context, or service name validation fails.
    pub fn build_service_describe_command(
        kubectl_bin: Option<&str>,
        service: &str,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        validate_dns_name(service)?;

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_val = namespace.unwrap_or("default");
        let ns_esc = shell_escape(ns_val);
        let svc_esc = shell_escape(service);

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "K={prefix_esc}; NS={ns_esc}; \
             echo '=== Service {svc_esc} ==='; \
             $K get svc {svc_esc} -n $NS -o wide{ctx_flag}; \
             echo '=== Spec (type/clusterIP/ports/selector) ==='; \
             $K get svc {svc_esc} -n $NS \
               -o jsonpath='type={{.spec.type}} clusterIP={{.spec.clusterIP}} \
ports={{.spec.ports[*].port}}/{{.spec.ports[*].targetPort}} \
selector={{.spec.selector}}'{ctx_flag}; \
             echo; \
             echo '=== Endpoints (ready addresses) ==='; \
             $K get endpoints {svc_esc} -n $NS \
               -o custom-columns='ENDPOINT:.metadata.name,\
ADDRS:.subsets[*].addresses[*].ip,\
PORTS:.subsets[*].ports[*].port'{ctx_flag}; \
             echo '=== klipper svclb (k3s LoadBalancer) ==='; \
             $K get pods -n kube-system \
               -l 'svccontroller.k3s.cattle.io/svcname={svc_esc}' \
               -o wide{ctx_flag} 2>/dev/null \
               || echo 'no svclb pods (not type=LoadBalancer or non-k3s)'",
            prefix_esc = shell_escape(prefix.trim_end()),
            ns_esc = ns_esc,
            svc_esc = svc_esc,
            ctx_flag = ctx_flag,
        );
        Ok(cmd)
    }

    /// Build an ephemeral connectivity test command.
    ///
    /// Runs a short-lived pod using `nc -z` to test reachability of
    /// `target_host:target_port`. The pod is cleaned up by both `--rm`
    /// and an explicit `kubectl delete pod` for safety.
    ///
    /// # Parameters
    ///
    /// * `kubectl_bin` — Optional explicit kubectl binary path.
    /// * `target_host` — DNS name or IP to test connectivity to.
    /// * `target_port` — TCP port to test (1–65535).
    /// * `namespace` — Optional Kubernetes namespace (default: `default`).
    /// * `image` — Optional container image (default: `busybox:1.36`).
    /// * `wait_secs` — Bounded wait duration in seconds (1–300, default 15).
    /// * `context` — Optional kubeconfig context.
    ///
    /// # Errors
    ///
    /// Returns an error if any input validation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn build_connectivity_test_command(
        kubectl_bin: Option<&str>,
        target_host: &str,
        target_port: u16,
        namespace: Option<&str>,
        image: Option<&str>,
        wait_secs: u64,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        validate_dns_name(target_host)?;
        validate_port(target_port)?;
        if let Some(img) = image {
            validate_probe_image(img)?;
        }
        validate_duration_secs(wait_secs)?;

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_val = namespace.unwrap_or("default");
        let ns_esc = shell_escape(ns_val);
        let image_val = image.unwrap_or("busybox:1.36");
        let image_esc = shell_escape(image_val);
        let host_esc = shell_escape(target_host);
        let port_str = target_port.to_string();
        let port_esc = shell_escape(&port_str);
        let wait_esc = shell_escape(&wait_secs.to_string());

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "POD=conn-probe-$$; K={prefix_esc}; \
             $K run $POD -n {ns_esc}{ctx_flag} \
               --image={image_esc} --restart=Never --command --attach --rm \
               --timeout={wait_esc}s -- sh -c \
               'nc -z -w 5 {host_esc} {port_esc} \
                && echo REACHABLE:{host_esc}:{port_esc} \
                || (echo UNREACHABLE:{host_esc}:{port_esc}; exit 1)'; \
             RC=$?; \
             $K delete pod $POD -n {ns_esc}{ctx_flag} --ignore-not-found --grace-period=1 \
               >/dev/null 2>&1; \
             exit $RC",
            prefix_esc = shell_escape(prefix.trim_end()),
            ns_esc = ns_esc,
            ctx_flag = ctx_flag,
            image_esc = image_esc,
            wait_esc = wait_esc,
            host_esc = host_esc,
            port_esc = port_esc,
        );
        Ok(cmd)
    }

    /// Build a bounded Traefik API introspection command.
    ///
    /// Discovers the Traefik pod by label, starts a bounded port-forward,
    /// curls `/api<api_path>`, then unconditionally kills the background
    /// process and cleans up the tmp log file.
    ///
    /// # Errors
    ///
    /// Returns an error if any input validation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn build_traefik_introspect_command(
        kubectl_bin: Option<&str>,
        api_path: &str,
        namespace: Option<&str>,
        api_port: u16,
        wait_secs: u64,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        validate_probe_path(api_path)?;
        validate_port(api_port)?;
        // wait_secs bounded to 1–30 for port-forward (same constraint as build_port_forward_command)
        if wait_secs == 0 || wait_secs > 30 {
            return Err(BridgeError::CommandDenied {
                reason: format!("traefik introspect wait_secs must be 1–30 (got {wait_secs})"),
            });
        }

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_val = namespace.unwrap_or("kube-system");
        let ns_esc = shell_escape(ns_val);
        let port_str = api_port.to_string();
        let port_esc = shell_escape(&port_str);
        let path_esc = shell_escape(api_path);
        let wait_esc = shell_escape(&wait_secs.to_string());

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "K={prefix_esc}; NS={ns_esc}; \
             POD=$($K get pods -n $NS -l 'app.kubernetes.io/name=traefik' \
               -o jsonpath='{{.items[0].metadata.name}}'{ctx_flag} 2>/dev/null); \
             if [ -z \"$POD\" ]; then echo 'ERROR: no traefik pod found in '$NS; exit 1; fi; \
             echo 'traefik pod: '$POD; \
             $K port-forward $POD -n $NS {port_esc}:{port_esc}{ctx_flag} \
               >/tmp/tpf.$$ 2>&1 & PF=$!; \
             sleep {wait_esc}; \
             if kill -0 $PF 2>/dev/null; then \
               echo '=== GET /api{path_esc} ==='; \
               curl -sS -m 8 'http://127.0.0.1:{port_esc}/api{path_esc}' \
                 || echo 'curl FAILED'; \
             else \
               echo '=== port-forward DIED ==='; cat /tmp/tpf.$$; \
             fi; \
             kill $PF 2>/dev/null; wait $PF 2>/dev/null; rm -f /tmp/tpf.$$",
            prefix_esc = shell_escape(prefix.trim_end()),
            ns_esc = ns_esc,
            port_esc = port_esc,
            ctx_flag = ctx_flag,
            wait_esc = wait_esc,
            path_esc = path_esc,
        );
        Ok(cmd)
    }

    /// Build a Traefik `IngressRoute` inspection command.
    ///
    /// Shows the `IngressRoute` YAML, routes (match → service:port + middlewares),
    /// referenced middleware details, and backend service endpoints.
    ///
    /// # Errors
    ///
    /// Returns an error if namespace, context, or route name validation fails.
    pub fn build_traefik_ingressroute_command(
        kubectl_bin: Option<&str>,
        route: &str,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        validate_dns_name(route)?;

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let ns_val = namespace.unwrap_or("default");
        let ns_esc = shell_escape(ns_val);
        let route_esc = shell_escape(route);

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "K={prefix_esc}; NS={ns_esc}; \
             echo '=== IngressRoute {route_esc} ==='; \
             $K get ingressroute.traefik.io {route_esc} -n $NS -o yaml{ctx_flag} 2>/dev/null \
               || $K get ingressroute.traefik.containo.us {route_esc} -n $NS -o yaml{ctx_flag}; \
             echo '=== routes: match -> service:port (+ middlewares) ==='; \
             $K get ingressroute.traefik.io {route_esc} -n $NS \
               -o jsonpath='{{range .spec.routes[*]}}match={{.match}} \
services={{range .services[*]}}{{.name}}:{{.port}}{{end}} \
middlewares={{range .middlewares[*]}}{{.name}}{{end}}{{\"\\n\"}}{{end}}'{ctx_flag} \
               2>/dev/null || echo '(v1alpha1 group)'; \
             echo; \
             echo '=== referenced Middlewares ==='; \
             for m in $($K get ingressroute.traefik.io {route_esc} -n $NS \
               -o jsonpath='{{.spec.routes[*].middlewares[*].name}}'{ctx_flag} 2>/dev/null); do \
               echo \"-- $m --\"; \
               $K get middleware.traefik.io $m -n $NS -o yaml{ctx_flag} 2>/dev/null \
                 || $K get middleware.traefik.containo.us $m -n $NS -o yaml{ctx_flag} 2>/dev/null \
                 || echo 'not found'; \
             done; \
             echo '=== backend service endpoints ==='; \
             for s in $($K get ingressroute.traefik.io {route_esc} -n $NS \
               -o jsonpath='{{.spec.routes[*].services[*].name}}'{ctx_flag} 2>/dev/null); do \
               echo \"-- $s --\"; \
               $K get endpoints $s -n $NS \
                 -o custom-columns='ADDRS:.subsets[*].addresses[*].ip,\
PORTS:.subsets[*].ports[*].port'{ctx_flag} 2>/dev/null || echo 'no endpoints'; \
             done",
            prefix_esc = shell_escape(prefix.trim_end()),
            ns_esc = ns_esc,
            route_esc = route_esc,
            ctx_flag = ctx_flag,
        );
        Ok(cmd)
    }

    /// Build a K3s `ServiceLB` status command.
    ///
    /// Shows all `type=LoadBalancer` services cluster-wide, klipper svclb
    /// daemonsets, and svclb pods with their host port mappings.
    ///
    /// # Errors
    ///
    /// Returns an error if namespace or context validation fails.
    pub fn build_servicelb_status_command(
        kubectl_bin: Option<&str>,
        namespace: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ns) = namespace {
            Self::validate_namespace(ns)?;
        }
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "K={prefix_esc}; \
             echo '=== type=LoadBalancer services ==='; \
             $K get svc -A --field-selector spec.type=LoadBalancer \
               -o custom-columns='NS:.metadata.namespace,\
NAME:.metadata.name,\
CLUSTER-IP:.spec.clusterIP,\
EXTERNAL-IP:.status.loadBalancer.ingress[*].ip,\
PORTS:.spec.ports[*].port'{ctx_flag}; \
             echo '=== klipper svclb daemonsets ==='; \
             $K get ds -n kube-system \
               -l 'svccontroller.k3s.cattle.io/svcname' \
               -o custom-columns='DS:.metadata.name,\
SVC:.metadata.labels.svccontroller\\.k3s\\.cattle\\.io/svcname,\
DESIRED:.status.desiredNumberScheduled,\
READY:.status.numberReady'{ctx_flag} 2>/dev/null \
               || echo 'no klipper svclb daemonsets (servicelb disabled or non-k3s)'; \
             echo '=== svclb pods -> node + hostPort ==='; \
             $K get pods -n kube-system \
               -l 'svccontroller.k3s.cattle.io/svcname' \
               -o custom-columns='POD:.metadata.name,\
SVC:.metadata.labels.svccontroller\\.k3s\\.cattle\\.io/svcname,\
NODE:.spec.nodeName,\
HOSTPORTS:.spec.containers[*].ports[*].hostPort,\
STATUS:.status.phase'{ctx_flag} 2>/dev/null \
               || echo 'no svclb pods'",
            prefix_esc = shell_escape(prefix.trim_end()),
            ctx_flag = ctx_flag,
        );
        Ok(cmd)
    }

    /// Build a K3s addon manifests inspection command.
    ///
    /// Lists the auto-deploy manifests directory, `HelmChart` CRDs (k3s addon
    /// installs), `HelmChart` job status, and helm-install jobs in kube-system.
    ///
    /// # Errors
    ///
    /// Returns an error if `manifests_dir` or context validation fails.
    pub fn build_addon_manifests_command(
        kubectl_bin: Option<&str>,
        manifests_dir: Option<&str>,
        context: Option<&str>,
    ) -> Result<String> {
        if let Some(ctx) = context {
            validate_context(ctx)?;
        }
        if let Some(dir) = manifests_dir {
            validate_abs_path(dir)?;
        }

        let prefix = kubectl_detect_prefix(kubectl_bin);
        let ctx_flag = kubectl_context_flag(context);
        let dir_val = manifests_dir.unwrap_or("/var/lib/rancher/k3s/server/manifests");
        let dir_esc = shell_escape(dir_val);

        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "K={prefix_esc}; DIR={dir_esc}; \
             echo '=== auto-deploy manifests ('$DIR') ==='; \
             ls -la \"$DIR\" 2>/dev/null \
               || echo 'manifests dir not present (need root/sudo or non-k3s host)'; \
             echo '=== HelmChart CRDs (k3s addon installs) ==='; \
             $K get helmchart -A \
               -o custom-columns='NS:.metadata.namespace,\
NAME:.metadata.name,\
CHART:.spec.chart,\
VERSION:.spec.version,\
REPO:.spec.repo,\
TARGETNS:.spec.targetNamespace'{ctx_flag} 2>/dev/null \
               || echo 'no HelmChart CRDs (helm-controller absent)'; \
             echo '=== HelmChart job status ==='; \
             $K get helmchart -A \
               -o jsonpath='{{range .items[*]}}{{.metadata.namespace}}/{{.metadata.name}}: \
jobName={{.status.jobName}}{{\"\\n\"}}{{end}}'{ctx_flag} 2>/dev/null; \
             echo '=== helm-install jobs ==='; \
             $K get jobs -n kube-system \
               -l 'helmcharts.helm.cattle.io/chart' \
               -o custom-columns='JOB:.metadata.name,\
COMPLETIONS:.status.succeeded,\
FAILED:.status.failed'{ctx_flag} 2>/dev/null \
               || echo 'no helm-install jobs'",
            prefix_esc = shell_escape(prefix.trim_end()),
            dir_esc = dir_esc,
            ctx_flag = ctx_flag,
        );
        Ok(cmd)
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
            false,
            false,
            false,
            None,
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
            false,
            false,
            false,
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
            false,
            false,
            false,
            None,
        );
        assert!(cmd.contains(" -A"));
    }

    #[test]
    fn test_build_get_command_auto_detect() {
        let cmd = KubernetesCommandBuilder::build_get_command(
            None, "pods", None, None, false, None, None, None, None, false, false, false, None,
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
            false,
            false,
            false,
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
            None,
            None,
            None,
        );
        assert!(cmd.contains("get events --sort-by=.lastTimestamp"));
        assert!(cmd.contains("-n 'default'"));
        assert!(cmd.contains("--field-selector 'involvedObject.name=p'"));
    }

    #[test]
    fn test_build_events_command_all_namespaces() {
        let cmd = KubernetesCommandBuilder::build_events_command(
            Some("kubectl"),
            None,
            true,
            None,
            None,
            None,
            None,
        );
        assert!(cmd.contains("get events --sort-by=.lastTimestamp"));
        assert!(cmd.contains("-A"));
        assert!(!cmd.contains("-n "));
    }

    #[test]
    fn test_build_events_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_events_command(
            Some("kubectl"),
            None,
            false,
            None,
            None,
            None,
            None,
        );
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
            None,
            false,
            None,
            false,
            None,
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
            None,
            false,
            None,
            false,
            None,
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
            None,
            false,
            None,
            false,
            None,
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
            None,
            false,
            None,
            false,
            None,
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
            Some("nginx-abc123"),
            Some("production"),
            None,
            false,
        );
        assert!(cmd.starts_with("kubectl describe 'pod' 'nginx-abc123'"));
        assert!(cmd.contains("-n 'production'"));
    }

    #[test]
    fn test_build_describe_command_minimal() {
        let cmd = KubernetesCommandBuilder::build_describe_command(
            Some("kubectl"),
            "node",
            Some("worker-1"),
            None,
            None,
            false,
        );
        assert_eq!(cmd, "kubectl describe 'node' 'worker-1'");
    }

    #[test]
    fn test_build_describe_command_special_chars() {
        let cmd = KubernetesCommandBuilder::build_describe_command(
            Some("kubectl"),
            "pod",
            Some("my-pod's-name"),
            None,
            None,
            false,
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
            Some("nginx"),
            Some("default"),
            Some(0),
            true,
            Some("client"),
            None,
            false,
            None,
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
            Some("nginx"),
            None,
            None,
            false,
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
            Some("nginx"),
            None,
            Some(30),
            false,
            None,
            None,
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
            None,
            None,
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
            None,
            None,
            None,
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
            None,
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
            Some("ls -la /tmp"),
            Some("default"),
            Some("nginx"),
            None,
            false,
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
            Some("whoami"),
            None,
            None,
            None,
            false,
        );
        assert_eq!(cmd, "kubectl exec 'my-pod' -- sh -c 'whoami'");
    }

    #[test]
    fn test_build_exec_command_with_namespace_only() {
        let cmd = KubernetesCommandBuilder::build_exec_command(
            Some("kubectl"),
            "my-pod",
            Some("date"),
            Some("kube-system"),
            None,
            None,
            false,
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
            false,
            false,
            None,
            None,
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
            false,
            false,
            None,
            None,
        );
        assert_eq!(cmd, "helm list");
    }

    #[test]
    fn test_helm_build_list_auto_detect() {
        let cmd = HelmCommandBuilder::build_list_command(
            None, None, None, false, false, None, None, false, false, None, None,
        );
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
            false,
            false,
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
            false,
            false,
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
            false,
            false,
            None,
            false,
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
            false,
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
            false,
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
            false,
            None,
            false,
            None,
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
            false,
            None,
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
            false,
            false,
            None,
            false,
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
            false,
            false,
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
            false,
            false,
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
            false,
            false,
            None,
            None,
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
            false,
            false,
            None,
            None,
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
            false,
            false,
            None,
            None,
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
            false,
            false,
            None,
            None,
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
            false,
            false,
            false,
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
            false, false, None, false,
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
            false,
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
            false,
            None,
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
            Some("ls; rm -rf /"),
            None,
            None,
            None,
            false,
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
            false,
            None,
            None,
            false,
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
            None,
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
        assert!(KubernetesCommandBuilder::validate_helm_get_subcommand("metadata").is_ok());

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
            false,
            None,
            None,
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

    // ============== validate_secret_type Tests ==============

    #[test]
    fn test_validate_secret_type_accepts_valid() {
        assert!(validate_secret_type("Opaque").is_ok());
        assert!(validate_secret_type("opaque").is_ok());
        assert!(validate_secret_type("generic").is_ok());
        assert!(validate_secret_type("tls").is_ok());
        assert!(validate_secret_type("docker-registry").is_ok());
    }

    #[test]
    fn test_validate_secret_type_rejects_invalid() {
        assert!(validate_secret_type("kubernetes.io/service-account-token").is_err());
        assert!(validate_secret_type("").is_err());
        assert!(validate_secret_type("basic-auth").is_err());
    }

    // ============== validate_secret_key Tests ==============

    #[test]
    fn test_validate_secret_key_accepts_valid() {
        assert!(validate_secret_key("my-key").is_ok());
        assert!(validate_secret_key("KEY_123").is_ok());
        assert!(validate_secret_key("a.b.c").is_ok());
    }

    #[test]
    fn test_validate_secret_key_rejects_flag_injection() {
        assert!(validate_secret_key("-flag").is_err());
        assert!(validate_secret_key("").is_err());
    }

    #[test]
    fn test_validate_secret_key_rejects_bad_charset() {
        assert!(validate_secret_key("key with space").is_err());
        assert!(validate_secret_key("key$").is_err());
        assert!(validate_secret_key("key;rm").is_err());
    }

    // ============== validate_jsonpath_key Tests ==============

    #[test]
    fn test_validate_jsonpath_key_rejects_quote_chars() {
        assert!(validate_jsonpath_key("k'ey").is_err());
        assert!(validate_jsonpath_key("k\"ey").is_err());
        assert!(validate_jsonpath_key("k\\ey").is_err());
        assert!(validate_jsonpath_key("k$ey").is_err());
    }

    #[test]
    fn test_validate_jsonpath_key_accepts_safe_key() {
        assert!(validate_jsonpath_key("my-key").is_ok());
        assert!(validate_jsonpath_key("TLS_CERT").is_ok());
    }

    // ============== build_create_secret_command Tests ==============

    #[test]
    fn test_build_create_secret_command_generic() {
        let cmd = KubernetesCommandBuilder::build_create_secret_command(
            Some("kubectl"),
            "my-secret",
            "generic",
            &[("api_key".to_string(), "s3cr3t!".to_string())],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("default"),
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("create secret generic"), "cmd: {cmd}");
        assert!(cmd.contains("my-secret"), "cmd: {cmd}");
        assert!(cmd.contains("--from-literal="), "cmd: {cmd}");
        assert!(cmd.contains("-n 'default'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_create_secret_command_tls() {
        let cmd = KubernetesCommandBuilder::build_create_secret_command(
            Some("kubectl"),
            "tls-secret",
            "tls",
            &[],
            &[],
            None,
            Some("/etc/certs/tls.crt"),
            Some("/etc/certs/tls.key"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("create secret tls"), "cmd: {cmd}");
        assert!(cmd.contains("--cert="), "cmd: {cmd}");
        assert!(cmd.contains("--key="), "cmd: {cmd}");
    }

    #[test]
    fn test_build_create_secret_command_docker_registry() {
        let cmd = KubernetesCommandBuilder::build_create_secret_command(
            Some("kubectl"),
            "regcred",
            "docker-registry",
            &[],
            &[],
            None,
            None,
            None,
            Some("registry.example.com"),
            Some("myuser"),
            Some("mypassword"),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("create secret docker-registry"), "cmd: {cmd}");
        assert!(cmd.contains("--docker-server="), "cmd: {cmd}");
        assert!(cmd.contains("--docker-username="), "cmd: {cmd}");
        assert!(cmd.contains("--docker-password="), "cmd: {cmd}");
    }

    #[test]
    fn test_build_create_secret_command_rejects_tls_missing_key() {
        let result = KubernetesCommandBuilder::build_create_secret_command(
            Some("kubectl"),
            "bad",
            "tls",
            &[],
            &[],
            None,
            Some("/cert.pem"),
            None, // missing key
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    // ============== build_create_configmap_command Tests ==============

    #[test]
    fn test_build_create_configmap_command_from_literal() {
        let cmd = KubernetesCommandBuilder::build_create_configmap_command(
            Some("kubectl"),
            "my-config",
            &[
                ("key1".to_string(), "value1".to_string()),
                ("key2".to_string(), "value2".to_string()),
            ],
            &[],
            None,
            Some("default"),
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("create configmap"), "cmd: {cmd}");
        assert!(cmd.contains("my-config"), "cmd: {cmd}");
        assert!(cmd.contains("--from-literal="), "cmd: {cmd}");
    }

    #[test]
    fn test_build_create_configmap_command_rejects_empty_sources() {
        let result = KubernetesCommandBuilder::build_create_configmap_command(
            Some("kubectl"),
            "empty-config",
            &[],
            &[],
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err(), "empty sources must be rejected");
    }

    // ============== build_secret_keys_command Tests ==============

    #[test]
    fn test_build_secret_keys_command() {
        let cmd = KubernetesCommandBuilder::build_secret_keys_command(
            Some("kubectl"),
            "my-secret",
            Some("prod"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("get secret"), "cmd: {cmd}");
        assert!(cmd.contains("my-secret"), "cmd: {cmd}");
        assert!(cmd.contains("go-template"), "cmd: {cmd}");
        assert!(!cmd.contains("base64"), "must not decode values: {cmd}");
    }

    // ============== build_secret_decode_command Tests ==============

    #[test]
    fn test_build_secret_decode_command() {
        let cmd = KubernetesCommandBuilder::build_secret_decode_command(
            Some("kubectl"),
            "my-secret",
            "api-key",
            Some("prod"),
            None,
            true,
        )
        .unwrap();
        assert!(cmd.contains("get secret"), "cmd: {cmd}");
        assert!(cmd.contains("jsonpath"), "cmd: {cmd}");
        assert!(cmd.contains("base64 -d"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_secret_decode_command_rejects_bad_key() {
        let result = KubernetesCommandBuilder::build_secret_decode_command(
            Some("kubectl"),
            "my-secret",
            "key'injection",
            None,
            None,
            true,
        );
        assert!(result.is_err(), "single quote in key must be rejected");
    }

    #[test]
    fn test_build_secret_decode_command_requires_reveal() {
        let result = KubernetesCommandBuilder::build_secret_decode_command(
            Some("kubectl"),
            "my-secret",
            "api-key",
            None,
            None,
            false,
        );
        match result {
            Err(crate::error::BridgeError::CommandDenied { reason }) => {
                assert!(
                    !reason.contains("api-key"),
                    "error must NOT contain key plaintext: {reason}"
                );
                assert!(
                    !reason.contains("my-secret"),
                    "error must NOT contain secret name: {reason}"
                );
            }
            Ok(cmd) => panic!("reveal=false must return Err, got: {cmd}"),
            Err(e) => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ============== build_secret_export_command Tests ==============

    #[test]
    fn test_build_secret_export_command() {
        let cmd = KubernetesCommandBuilder::build_secret_export_command(
            Some("kubectl"),
            "my-secret",
            Some("prod"),
            None,
            true,
        )
        .unwrap();
        assert!(cmd.contains("get secret"), "cmd: {cmd}");
        assert!(cmd.contains("-o yaml"), "cmd: {cmd}");
        assert!(cmd.contains("grep -v"), "cmd: {cmd}");
        assert!(cmd.contains("managedFields"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_secret_export_command_requires_reveal() {
        let result = KubernetesCommandBuilder::build_secret_export_command(
            Some("kubectl"),
            "my-secret",
            None,
            None,
            false,
        );
        match result {
            Err(crate::error::BridgeError::CommandDenied { reason }) => {
                assert!(
                    !reason.contains("my-secret"),
                    "error must NOT contain secret name: {reason}"
                );
            }
            Ok(cmd) => panic!("reveal=false must return Err, got: {cmd}"),
            Err(e) => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ============== HelmCommandBuilder New Tests ==============

    #[test]
    fn test_build_repo_add_command() {
        let cmd = HelmCommandBuilder::build_repo_add_command(
            Some("helm"),
            "myrepo",
            "https://charts.example.com/",
            None,
            None,
            false,
            false,
        );
        assert!(cmd.contains("helm repo add 'myrepo' 'https://charts.example.com/'"));
    }

    #[test]
    fn test_build_repo_update_command() {
        let cmd = HelmCommandBuilder::build_repo_update_command(Some("helm"), None);
        assert!(cmd.contains("helm repo update"));
    }

    #[test]
    fn test_build_repo_list_command() {
        let cmd = HelmCommandBuilder::build_repo_list_command(Some("helm"), None);
        assert!(cmd.contains("helm repo list"));
    }

    #[test]
    fn test_build_repo_remove_command() {
        let names = vec!["myrepo".to_string()];
        let cmd = HelmCommandBuilder::build_repo_remove_command(Some("helm"), &names).unwrap();
        assert!(cmd.contains("helm repo remove 'myrepo'"));
    }

    #[test]
    fn test_build_repo_remove_command_empty_fails() {
        let result = HelmCommandBuilder::build_repo_remove_command(Some("helm"), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_show_command() {
        let cmd = HelmCommandBuilder::build_show_command(
            Some("helm"),
            "values",
            "stable/nginx",
            None,
            None,
            false,
        );
        assert!(cmd.contains("helm show 'values' 'stable/nginx'"));
    }

    #[test]
    fn test_build_pull_command() {
        let cmd = HelmCommandBuilder::build_pull_command(
            Some("helm"),
            "stable/nginx",
            None,
            None,
            false,
            None,
            false,
            false,
        );
        assert!(cmd.contains("helm pull 'stable/nginx'"));
    }

    #[test]
    fn test_build_lint_command() {
        let cmd = HelmCommandBuilder::build_lint_command(
            Some("helm"),
            "/path/to/chart",
            false,
            None,
            None,
            false,
        );
        assert!(cmd.contains("helm lint '/path/to/chart'"));
    }

    #[test]
    fn test_build_dependency_command() {
        let cmd = HelmCommandBuilder::build_dependency_command(
            Some("helm"),
            "build",
            "/path/to/chart",
            false,
            false,
        );
        assert!(cmd.contains("helm dependency 'build' '/path/to/chart'"));
    }

    #[test]
    fn test_build_diff_command() {
        let cmd = HelmCommandBuilder::build_diff_command(
            Some("helm"),
            "upgrade",
            "myrelease",
            Some("stable/nginx"),
            None,
            None,
            None,
            None,
            false,
        );
        assert!(cmd.contains("helm diff 'upgrade' 'myrelease'"));
        assert!(cmd.contains("helm-diff plugin not installed"));
    }

    #[test]
    fn test_build_test_command() {
        let cmd = HelmCommandBuilder::build_test_command(
            Some("helm"),
            None,
            "myrelease",
            None,
            false,
            None,
            None,
        );
        assert!(cmd.contains("helm test 'myrelease'"));
    }

    #[test]
    fn test_build_search_repo_command() {
        let cmd = HelmCommandBuilder::build_search_repo_command(
            Some("helm"),
            "nginx",
            None,
            false,
            false,
            None,
            false,
        );
        assert!(cmd.contains("helm search repo 'nginx'"));
    }

    #[test]
    fn test_build_plugin_list_command() {
        let cmd = HelmCommandBuilder::build_plugin_list_command(Some("helm"));
        assert!(cmd.contains("helm plugin list"));
    }

    #[test]
    fn test_validate_repo_name_valid() {
        assert!(HelmCommandBuilder::validate_repo_name("my-repo").is_ok());
        assert!(HelmCommandBuilder::validate_repo_name("repo.1").is_ok());
    }

    #[test]
    fn test_validate_repo_name_invalid() {
        assert!(HelmCommandBuilder::validate_repo_name("").is_err());
        assert!(HelmCommandBuilder::validate_repo_name("-bad").is_err());
        assert!(HelmCommandBuilder::validate_repo_name("bad name").is_err());
    }

    #[test]
    fn test_validate_repo_url_valid() {
        assert!(HelmCommandBuilder::validate_repo_url("https://charts.example.com/").is_ok());
        assert!(HelmCommandBuilder::validate_repo_url("oci://registry.example.com/charts").is_ok());
    }

    #[test]
    fn test_validate_repo_url_invalid() {
        assert!(HelmCommandBuilder::validate_repo_url("").is_err());
        assert!(HelmCommandBuilder::validate_repo_url("ftp://bad.com").is_err());
        assert!(HelmCommandBuilder::validate_repo_url("https://bad;cmd").is_err());
    }

    #[test]
    fn test_validate_helm_output_valid() {
        assert!(HelmCommandBuilder::validate_helm_output("json").is_ok());
        assert!(HelmCommandBuilder::validate_helm_output("yaml").is_ok());
        assert!(HelmCommandBuilder::validate_helm_output("table").is_ok());
    }

    #[test]
    fn test_validate_helm_output_invalid() {
        assert!(HelmCommandBuilder::validate_helm_output("xml").is_err());
        assert!(HelmCommandBuilder::validate_helm_output("--flag").is_err());
    }

    #[test]
    fn test_validate_show_subcommand_valid() {
        for sub in &["all", "chart", "readme", "values", "crds"] {
            assert!(HelmCommandBuilder::validate_show_subcommand(sub).is_ok());
        }
    }

    #[test]
    fn test_validate_show_subcommand_invalid() {
        assert!(HelmCommandBuilder::validate_show_subcommand("bad").is_err());
    }

    #[test]
    fn test_validate_dependency_subcommand_valid() {
        for sub in &["build", "update", "list"] {
            assert!(HelmCommandBuilder::validate_dependency_subcommand(sub).is_ok());
        }
    }

    #[test]
    fn test_validate_dependency_subcommand_invalid() {
        assert!(HelmCommandBuilder::validate_dependency_subcommand("bad").is_err());
    }

    #[test]
    fn test_validate_diff_subcommand_valid() {
        for sub in &["upgrade", "rollback", "release", "revision"] {
            assert!(HelmCommandBuilder::validate_diff_subcommand(sub).is_ok());
        }
    }

    #[test]
    fn test_validate_diff_subcommand_invalid() {
        assert!(HelmCommandBuilder::validate_diff_subcommand("bad").is_err());
    }

    // ============================================================
    // Wave-9a: Networking validator tests
    // ============================================================

    // --- validate_port ---

    #[test]
    fn test_validate_port_accepts_valid_range() {
        assert!(validate_port(1).is_ok());
        assert!(validate_port(80).is_ok());
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(65535).is_ok());
    }

    #[test]
    fn test_validate_port_rejects_zero() {
        let err = validate_port(0).unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => assert!(reason.contains("1–65535")),
            e => panic!("expected CommandDenied, got {e:?}"),
        }
    }

    // --- validate_probe_path ---

    #[test]
    fn test_validate_probe_path_accepts_valid() {
        assert!(validate_probe_path("/").is_ok());
        assert!(validate_probe_path("/healthz").is_ok());
        assert!(validate_probe_path("/api/v1?foo=bar").is_ok());
        assert!(validate_probe_path("/metrics").is_ok());
    }

    #[test]
    fn test_validate_probe_path_rejects_empty() {
        assert!(validate_probe_path("").is_err());
    }

    #[test]
    fn test_validate_probe_path_rejects_no_leading_slash() {
        assert!(validate_probe_path("healthz").is_err());
    }

    #[test]
    fn test_validate_probe_path_rejects_traversal() {
        assert!(validate_probe_path("/../etc/passwd").is_err());
        assert!(validate_probe_path("/foo/../bar").is_err());
    }

    #[test]
    fn test_validate_probe_path_rejects_injection() {
        assert!(validate_probe_path("/foo\nbar").is_err());
        assert!(validate_probe_path("/foo bar").is_err());
        assert!(validate_probe_path("/foo`bar").is_err());
        assert!(validate_probe_path("/$(ls)").is_err());
    }

    // --- validate_dns_name ---

    #[test]
    fn test_validate_dns_name_accepts_valid() {
        assert!(validate_dns_name("myservice").is_ok());
        assert!(validate_dns_name("my-service").is_ok());
        assert!(validate_dns_name("svc.ns").is_ok());
        assert!(validate_dns_name("web-01").is_ok());
    }

    #[test]
    fn test_validate_dns_name_rejects_empty() {
        assert!(validate_dns_name("").is_err());
    }

    #[test]
    fn test_validate_dns_name_rejects_leading_dash() {
        assert!(validate_dns_name("-bad").is_err());
    }

    #[test]
    fn test_validate_dns_name_rejects_trailing_dash() {
        assert!(validate_dns_name("bad-").is_err());
    }

    #[test]
    fn test_validate_dns_name_rejects_uppercase() {
        assert!(validate_dns_name("MyService").is_err());
    }

    // --- validate_probe_image ---

    #[test]
    fn test_validate_probe_image_accepts_valid() {
        assert!(validate_probe_image("busybox:1.36").is_ok());
        assert!(validate_probe_image("registry.example.com/myimage:latest").is_ok());
        assert!(validate_probe_image("my-image@sha256:abc123").is_ok());
    }

    #[test]
    fn test_validate_probe_image_rejects_empty() {
        assert!(validate_probe_image("").is_err());
    }

    #[test]
    fn test_validate_probe_image_rejects_leading_dash() {
        assert!(validate_probe_image("-bad").is_err());
    }

    #[test]
    fn test_validate_probe_image_rejects_injection() {
        assert!(validate_probe_image("busybox;rm -rf").is_err());
    }

    // --- validate_duration_secs ---

    #[test]
    fn test_validate_duration_secs_accepts_valid() {
        assert!(validate_duration_secs(1).is_ok());
        assert!(validate_duration_secs(30).is_ok());
        assert!(validate_duration_secs(300).is_ok());
    }

    #[test]
    fn test_validate_duration_secs_rejects_zero() {
        assert!(validate_duration_secs(0).is_err());
    }

    #[test]
    fn test_validate_duration_secs_rejects_above_cap() {
        assert!(validate_duration_secs(301).is_err());
        assert!(validate_duration_secs(3600).is_err());
    }

    // --- validate_proxy_resource ---

    #[test]
    fn test_validate_proxy_resource_accepts_valid() {
        assert!(validate_proxy_resource("services").is_ok());
        assert!(validate_proxy_resource("pods").is_ok());
    }

    #[test]
    fn test_validate_proxy_resource_rejects_invalid() {
        assert!(validate_proxy_resource("deployments").is_err());
        assert!(validate_proxy_resource("").is_err());
        assert!(validate_proxy_resource("nodes").is_err());
    }

    // ============================================================
    // Wave-9a: build_port_forward_command tests
    // ============================================================

    #[test]
    fn test_build_port_forward_command_basic() {
        let cmd = KubernetesCommandBuilder::build_port_forward_command(
            Some("kubectl"),
            "svc/myapp",
            "8080:80",
            None,
            5,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("kubectl port-forward"), "cmd: {cmd}");
        assert!(cmd.contains("'svc/myapp'"), "cmd: {cmd}");
        assert!(cmd.contains("'8080:80'"), "cmd: {cmd}");
        assert!(cmd.contains("sleep '5'"), "cmd: {cmd}");
        assert!(cmd.contains("kill $PF"), "cmd: {cmd}");
        assert!(cmd.contains("rm -f /tmp/pf.$$"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_port_forward_command_with_probe() {
        let cmd = KubernetesCommandBuilder::build_port_forward_command(
            Some("kubectl"),
            "svc/web",
            "8080:80",
            Some("/healthz"),
            10,
            Some("default"),
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("curl"), "cmd: {cmd}");
        assert!(cmd.contains("/healthz"), "cmd: {cmd}");
        assert!(cmd.contains("-n 'default'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_port_forward_command_rejects_zero_wait() {
        let result = KubernetesCommandBuilder::build_port_forward_command(
            Some("kubectl"),
            "svc/web",
            "8080:80",
            None,
            0,
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_port_forward_command_rejects_wait_above_30() {
        let result = KubernetesCommandBuilder::build_port_forward_command(
            Some("kubectl"),
            "svc/web",
            "8080:80",
            None,
            31,
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_port_forward_command_rejects_invalid_probe_path() {
        let result = KubernetesCommandBuilder::build_port_forward_command(
            Some("kubectl"),
            "svc/web",
            "8080:80",
            Some("/../evil"),
            5,
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_port_forward_command_self_terminates() {
        // Verify the command always contains kill + wait + rm cleanup
        let cmd = KubernetesCommandBuilder::build_port_forward_command(
            Some("kubectl"),
            "pod/mypod",
            "9090",
            None,
            3,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("kill $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("wait $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("rm -f /tmp/pf.$$"), "cmd: {cmd}");
    }

    // ============================================================
    // Wave-9a: build_endpoints_command tests
    // ============================================================

    #[test]
    fn test_build_endpoints_command_basic() {
        let cmd = KubernetesCommandBuilder::build_endpoints_command(
            Some("kubectl"),
            "my-svc",
            Some("default"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("'my-svc'"), "cmd: {cmd}");
        assert!(cmd.contains("'default'"), "cmd: {cmd}");
        assert!(cmd.contains("Selector"), "cmd: {cmd}");
        assert!(cmd.contains("EndpointSlice"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_endpoints_command_rejects_invalid_svc() {
        let result = KubernetesCommandBuilder::build_endpoints_command(
            Some("kubectl"),
            "BadService",
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_endpoints_command_with_context() {
        let cmd = KubernetesCommandBuilder::build_endpoints_command(
            Some("kubectl"),
            "api",
            None,
            Some("prod"),
        )
        .unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }

    // ============================================================
    // Wave-9a: build_ingress_describe_command tests
    // ============================================================

    #[test]
    fn test_build_ingress_describe_command_basic() {
        let cmd = KubernetesCommandBuilder::build_ingress_describe_command(
            Some("kubectl"),
            "my-ingress",
            Some("production"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("'my-ingress'"), "cmd: {cmd}");
        assert!(cmd.contains("'production'"), "cmd: {cmd}");
        assert!(cmd.contains("backend"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_ingress_describe_command_rejects_invalid_name() {
        let result = KubernetesCommandBuilder::build_ingress_describe_command(
            Some("kubectl"),
            "My-Ingress",
            None,
            None,
        );
        assert!(result.is_err());
    }

    // ============================================================
    // Wave-9a: build_networkpolicy_command tests
    // ============================================================

    #[test]
    fn test_build_networkpolicy_command_basic() {
        let cmd = KubernetesCommandBuilder::build_networkpolicy_command(
            Some("kubectl"),
            "allow-web",
            Some("default"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("'allow-web'"), "cmd: {cmd}");
        assert!(cmd.contains("networkpolicy"), "cmd: {cmd}");
        assert!(cmd.contains("flannel"), "cmd: {cmd}");
        assert!(cmd.contains("podSelector"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_networkpolicy_command_rejects_invalid_policy() {
        let result = KubernetesCommandBuilder::build_networkpolicy_command(
            Some("kubectl"),
            "Bad Policy",
            None,
            None,
        );
        assert!(result.is_err());
    }

    // ============================================================
    // Wave-9a: build_proxy_get_command tests
    // ============================================================

    #[test]
    fn test_build_proxy_get_command_basic() {
        let cmd = KubernetesCommandBuilder::build_proxy_get_command(
            Some("kubectl"),
            "services",
            "myservice",
            "/healthz",
            None,
            Some("default"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("get --raw"), "cmd: {cmd}");
        assert!(
            cmd.contains("/api/v1/namespaces/default/services/myservice/proxy/healthz"),
            "cmd: {cmd}"
        );
    }

    #[test]
    fn test_build_proxy_get_command_with_port() {
        let cmd = KubernetesCommandBuilder::build_proxy_get_command(
            Some("kubectl"),
            "services",
            "myservice",
            "/metrics",
            Some(9090),
            Some("monitoring"),
            None,
        )
        .unwrap();
        assert!(
            cmd.contains("/api/v1/namespaces/monitoring/services/myservice:9090/proxy/metrics"),
            "cmd: {cmd}"
        );
    }

    #[test]
    fn test_build_proxy_get_command_rejects_bad_path() {
        let result = KubernetesCommandBuilder::build_proxy_get_command(
            Some("kubectl"),
            "services",
            "myservice",
            "/../etc/passwd",
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_proxy_get_command_rejects_bad_resource() {
        let result = KubernetesCommandBuilder::build_proxy_get_command(
            Some("kubectl"),
            "deployments",
            "myapp",
            "/healthz",
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    // ============================================================
    // Wave-9a: build_dns_check_command tests
    // ============================================================

    #[test]
    fn test_build_dns_check_command_basic() {
        let cmd =
            KubernetesCommandBuilder::build_dns_check_command(Some("kubectl"), None, None, None)
                .unwrap();
        assert!(cmd.contains("CoreDNS"), "cmd: {cmd}");
        assert!(cmd.contains("coredns"), "cmd: {cmd}");
        assert!(cmd.contains("Corefile"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_dns_check_command_with_resolve() {
        let cmd = KubernetesCommandBuilder::build_dns_check_command(
            Some("kubectl"),
            Some("kubernetes.default.svc.cluster.local"),
            None,
            None,
        )
        .unwrap();
        assert!(
            cmd.contains("kubernetes.default.svc.cluster.local"),
            "cmd: {cmd}"
        );
        assert!(cmd.contains("nslookup"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_dns_check_command_rejects_invalid_resolve_name() {
        let result = KubernetesCommandBuilder::build_dns_check_command(
            Some("kubectl"),
            Some("Bad Name!"),
            None,
            None,
        );
        assert!(result.is_err());
    }

    // ============================================================
    // Wave-9b: validate_abs_path tests
    // ============================================================

    #[test]
    fn test_validate_abs_path_accepts_valid() {
        assert!(validate_abs_path("/var/lib/rancher/k3s/server/manifests").is_ok());
        assert!(validate_abs_path("/tmp").is_ok());
        assert!(validate_abs_path("/etc/k3s").is_ok());
        assert!(validate_abs_path("/data/k3s-manifests").is_ok());
    }

    #[test]
    fn test_validate_abs_path_rejects_empty() {
        assert!(validate_abs_path("").is_err());
    }

    #[test]
    fn test_validate_abs_path_rejects_relative() {
        assert!(validate_abs_path("var/lib/manifests").is_err());
        assert!(validate_abs_path("./manifests").is_err());
    }

    #[test]
    fn test_validate_abs_path_rejects_traversal() {
        assert!(validate_abs_path("/var/lib/../etc/passwd").is_err());
        assert!(validate_abs_path("/../etc").is_err());
    }

    #[test]
    fn test_validate_abs_path_rejects_injection() {
        assert!(validate_abs_path("/tmp; rm -rf /").is_err());
        assert!(validate_abs_path("/tmp$(whoami)").is_err());
    }

    // ============================================================
    // Wave-9b: build_service_describe_command tests
    // ============================================================

    #[test]
    fn test_build_service_describe_command_basic() {
        let cmd = KubernetesCommandBuilder::build_service_describe_command(
            Some("kubectl"),
            "my-svc",
            Some("default"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("'my-svc'"), "cmd: {cmd}");
        assert!(cmd.contains("'default'"), "cmd: {cmd}");
        assert!(cmd.contains("=== Service"), "cmd: {cmd}");
        assert!(cmd.contains("=== Endpoints"), "cmd: {cmd}");
        assert!(cmd.contains("klipper svclb"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_service_describe_command_rejects_invalid_svc() {
        let result = KubernetesCommandBuilder::build_service_describe_command(
            Some("kubectl"),
            "BadService",
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_service_describe_command_with_context() {
        let cmd = KubernetesCommandBuilder::build_service_describe_command(
            Some("kubectl"),
            "api",
            None,
            Some("prod"),
        )
        .unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }

    // ============================================================
    // Wave-9b: build_connectivity_test_command tests
    // ============================================================

    #[test]
    fn test_build_connectivity_test_command_basic() {
        let cmd = KubernetesCommandBuilder::build_connectivity_test_command(
            Some("kubectl"),
            "my-service",
            8080,
            Some("default"),
            None,
            15,
            None,
        )
        .unwrap();
        assert!(cmd.contains("conn-probe-$$"), "cmd: {cmd}");
        assert!(cmd.contains("'my-service'"), "cmd: {cmd}");
        assert!(cmd.contains("'8080'"), "cmd: {cmd}");
        assert!(cmd.contains("nc -z -w 5"), "cmd: {cmd}");
        assert!(cmd.contains("REACHABLE"), "cmd: {cmd}");
        assert!(cmd.contains("--ignore-not-found"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_connectivity_test_command_has_double_cleanup() {
        // Both --rm and explicit delete must be present
        let cmd = KubernetesCommandBuilder::build_connectivity_test_command(
            Some("kubectl"),
            "redis",
            6379,
            None,
            None,
            10,
            None,
        )
        .unwrap();
        assert!(cmd.contains("--rm"), "cmd must have --rm: {cmd}");
        assert!(
            cmd.contains("delete pod"),
            "cmd must have explicit delete: {cmd}"
        );
        assert!(cmd.contains("--ignore-not-found"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_connectivity_test_command_rejects_zero_port() {
        let result = KubernetesCommandBuilder::build_connectivity_test_command(
            Some("kubectl"),
            "my-service",
            0,
            None,
            None,
            15,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_connectivity_test_command_rejects_invalid_host() {
        let result = KubernetesCommandBuilder::build_connectivity_test_command(
            Some("kubectl"),
            "BadHost",
            80,
            None,
            None,
            15,
            None,
        );
        assert!(result.is_err());
    }

    // ============================================================
    // Wave-9b: build_traefik_introspect_command tests
    // ============================================================

    #[test]
    fn test_build_traefik_introspect_command_basic() {
        let cmd = KubernetesCommandBuilder::build_traefik_introspect_command(
            Some("kubectl"),
            "/rawdata",
            None,
            8080,
            5,
            None,
        )
        .unwrap();
        assert!(cmd.contains("app.kubernetes.io/name=traefik"), "cmd: {cmd}");
        assert!(cmd.contains("port-forward"), "cmd: {cmd}");
        assert!(cmd.contains(">/tmp/tpf.$$"), "cmd: {cmd}");
        assert!(cmd.contains("kill $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("wait $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("rm -f /tmp/tpf.$$"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_traefik_introspect_command_self_terminates() {
        let cmd = KubernetesCommandBuilder::build_traefik_introspect_command(
            Some("kubectl"),
            "/rawdata",
            Some("kube-system"),
            8080,
            5,
            None,
        )
        .unwrap();
        assert!(cmd.contains("kill $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("wait $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("rm -f /tmp/tpf.$$"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_traefik_introspect_command_rejects_wait_above_30() {
        let result = KubernetesCommandBuilder::build_traefik_introspect_command(
            Some("kubectl"),
            "/rawdata",
            None,
            8080,
            31,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_traefik_introspect_command_rejects_zero_port() {
        let result = KubernetesCommandBuilder::build_traefik_introspect_command(
            Some("kubectl"),
            "/rawdata",
            None,
            0,
            5,
            None,
        );
        assert!(result.is_err());
    }

    // ============================================================
    // Wave-9b: build_traefik_ingressroute_command tests
    // ============================================================

    #[test]
    fn test_build_traefik_ingressroute_command_basic() {
        let cmd = KubernetesCommandBuilder::build_traefik_ingressroute_command(
            Some("kubectl"),
            "my-route",
            Some("default"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("'my-route'"), "cmd: {cmd}");
        assert!(cmd.contains("IngressRoute"), "cmd: {cmd}");
        assert!(cmd.contains("Middlewares"), "cmd: {cmd}");
        assert!(cmd.contains("backend service endpoints"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_traefik_ingressroute_command_rejects_invalid_route() {
        let result = KubernetesCommandBuilder::build_traefik_ingressroute_command(
            Some("kubectl"),
            "BadRoute",
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_traefik_ingressroute_command_with_context() {
        let cmd = KubernetesCommandBuilder::build_traefik_ingressroute_command(
            Some("kubectl"),
            "web-route",
            None,
            Some("prod"),
        )
        .unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }

    // ============================================================
    // Wave-9b: build_servicelb_status_command tests
    // ============================================================

    #[test]
    fn test_build_servicelb_status_command_basic() {
        let cmd =
            KubernetesCommandBuilder::build_servicelb_status_command(Some("kubectl"), None, None)
                .unwrap();
        assert!(cmd.contains("type=LoadBalancer"), "cmd: {cmd}");
        assert!(cmd.contains("klipper svclb daemonsets"), "cmd: {cmd}");
        assert!(cmd.contains("svclb pods"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_servicelb_status_command_with_context() {
        let cmd = KubernetesCommandBuilder::build_servicelb_status_command(
            Some("kubectl"),
            None,
            Some("prod"),
        )
        .unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_servicelb_status_command_rejects_invalid_namespace() {
        let result = KubernetesCommandBuilder::build_servicelb_status_command(
            Some("kubectl"),
            Some("--all-namespaces"),
            None,
        );
        assert!(result.is_err());
    }

    // ============================================================
    // Wave-9b: build_addon_manifests_command tests
    // ============================================================

    #[test]
    fn test_build_addon_manifests_command_basic() {
        let cmd =
            KubernetesCommandBuilder::build_addon_manifests_command(Some("kubectl"), None, None)
                .unwrap();
        assert!(cmd.contains("rancher/k3s/server/manifests"), "cmd: {cmd}");
        assert!(cmd.contains("HelmChart CRDs"), "cmd: {cmd}");
        assert!(cmd.contains("helm-install jobs"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_addon_manifests_command_custom_dir() {
        let cmd = KubernetesCommandBuilder::build_addon_manifests_command(
            Some("kubectl"),
            Some("/custom/manifests"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("'/custom/manifests'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_addon_manifests_command_rejects_relative_dir() {
        let result = KubernetesCommandBuilder::build_addon_manifests_command(
            Some("kubectl"),
            Some("relative/path"),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_addon_manifests_command_rejects_traversal() {
        let result = KubernetesCommandBuilder::build_addon_manifests_command(
            Some("kubectl"),
            Some("/var/lib/../etc"),
            None,
        );
        assert!(result.is_err());
    }
}
