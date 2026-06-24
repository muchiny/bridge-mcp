//! crictl Command Builder
//!
//! Builds `crictl` (CRI) commands for remote execution on K3s nodes, where
//! containers run under the embedded containerd (no dockerd). Auto-detects
//! `k3s crictl`, falling back to a standalone `crictl` pinned to the k3s
//! containerd socket.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

fn is_valid_binary_path(bin: &str) -> bool {
    !bin.is_empty()
        && bin
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

/// Generate the crictl detection prefix.
///
/// Prefers `k3s crictl`; falls back to a standalone `crictl` pinned to the
/// k3s containerd socket. If `crictl_bin` is supplied and valid, uses it
/// verbatim.
#[must_use]
pub fn crictl_detect_prefix(crictl_bin: Option<&str>) -> String {
    if let Some(bin) = crictl_bin
        && is_valid_binary_path(bin)
    {
        return format!("{bin} ");
    }
    "$(if command -v k3s &>/dev/null; then echo 'k3s crictl'; \
     elif command -v crictl &>/dev/null; then \
     echo 'crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock'; \
     else echo 'k3s/crictl not installed on host' >&2; echo false; fi) "
        .to_string()
}

/// Validate a CRI container/pod ID: non-empty, not flag-like, safe charset.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] on empty, leading `-`, or any
/// character outside `[A-Za-z0-9._:/-]`.
pub fn validate_container_id(id: &str) -> Result<()> {
    if id.is_empty() || id.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("invalid container id: {id}"),
        });
    }
    if !id
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | ':' | '/' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("container id contains disallowed characters: {id}"),
        });
    }
    Ok(())
}

/// Validate a CRI pod state filter.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] if `state` is not one of
/// `ready` or `notready`.
pub fn validate_pod_state(state: &str) -> Result<()> {
    match state {
        "ready" | "notready" => Ok(()),
        _ => Err(BridgeError::CommandDenied {
            reason: format!("invalid pod state '{state}': must be 'ready' or 'notready'"),
        }),
    }
}

/// Validate a CRI image reference: non-empty, not flag-like, safe charset.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] on empty, leading `-`, or any
/// character outside `[A-Za-z0-9._:/@-]`.
pub fn validate_image_ref(img: &str) -> Result<()> {
    if img.is_empty() || img.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("invalid image ref: {img}"),
        });
    }
    if !img
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | ':' | '/' | '@' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("image ref contains disallowed characters: {img}"),
        });
    }
    Ok(())
}

/// Validate a CRI inspect kind: must be one of `container`, `pod`, or `image`.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] if `kind` is not in the allowlist.
pub fn validate_inspect_kind(kind: &str) -> Result<()> {
    match kind {
        "container" | "pod" | "image" => Ok(()),
        _ => Err(BridgeError::CommandDenied {
            reason: format!(
                "invalid inspect kind '{kind}': must be 'container', 'pod', or 'image'"
            ),
        }),
    }
}

/// Builds crictl CLI commands.
pub struct CrictlCommandBuilder;

impl CrictlCommandBuilder {
    /// Build a `crictl ps` command (defaults to JSON output for reduction).
    #[must_use]
    pub fn build_ps_command(
        crictl_bin: Option<&str>,
        all: bool,
        state: Option<&str>,
        name: Option<&str>,
        label: Option<&str>,
        output: Option<&str>,
    ) -> String {
        use std::fmt::Write;
        let prefix = crictl_detect_prefix(crictl_bin);
        let mut cmd = format!("{prefix}ps");
        if all {
            cmd.push_str(" -a");
        }
        if let Some(s) = state {
            let _ = write!(cmd, " --state {}", shell_escape(s));
        }
        if let Some(n) = name {
            let _ = write!(cmd, " --name {}", shell_escape(n));
        }
        if let Some(l) = label {
            let _ = write!(cmd, " --label {}", shell_escape(l));
        }
        let _ = write!(cmd, " -o {}", shell_escape(output.unwrap_or("json")));
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── crictl_detect_prefix ──────────────────────────────────────────────────

    #[test]
    fn test_detect_prefix_explicit_bin() {
        let prefix = crictl_detect_prefix(Some("crictl"));
        assert_eq!(prefix, "crictl ");
    }

    #[test]
    fn test_detect_prefix_explicit_full_path() {
        let prefix = crictl_detect_prefix(Some("/usr/local/bin/crictl"));
        assert_eq!(prefix, "/usr/local/bin/crictl ");
    }

    #[test]
    fn test_detect_prefix_none_uses_subshell() {
        let prefix = crictl_detect_prefix(None);
        assert!(prefix.contains("k3s"), "prefix should prefer k3s crictl");
        assert!(prefix.contains("command -v"), "prefix should auto-detect");
    }

    #[test]
    fn test_detect_prefix_invalid_bin_falls_back_to_subshell() {
        // A bin with shell metacharacters is invalid; should fall back
        let prefix = crictl_detect_prefix(Some("crictl; rm -rf /"));
        assert!(
            prefix.contains("command -v"),
            "invalid bin should fall back to auto-detect"
        );
    }

    // ── validate_container_id ─────────────────────────────────────────────────

    #[test]
    fn test_validate_container_id_valid_hex() {
        assert!(validate_container_id("a1b2c3d4e5f6").is_ok());
    }

    #[test]
    fn test_validate_container_id_valid_with_dots_dashes() {
        assert!(validate_container_id("my-container.1:latest/subpath").is_ok());
    }

    #[test]
    fn test_validate_container_id_empty_rejected() {
        let err = validate_container_id("").unwrap_err();
        assert!(matches!(err, BridgeError::CommandDenied { .. }));
    }

    #[test]
    fn test_validate_container_id_flag_like_rejected() {
        let err = validate_container_id("-abc123").unwrap_err();
        assert!(matches!(err, BridgeError::CommandDenied { .. }));
    }

    #[test]
    fn test_validate_container_id_shell_chars_rejected() {
        let err = validate_container_id("abc$(rm -rf /)").unwrap_err();
        assert!(matches!(err, BridgeError::CommandDenied { .. }));
    }

    // ── validate_pod_state ────────────────────────────────────────────────────

    #[test]
    fn test_validate_pod_state_ready() {
        assert!(validate_pod_state("ready").is_ok());
    }

    #[test]
    fn test_validate_pod_state_notready() {
        assert!(validate_pod_state("notready").is_ok());
    }

    #[test]
    fn test_validate_pod_state_invalid_rejected() {
        let err = validate_pod_state("running").unwrap_err();
        assert!(matches!(err, BridgeError::CommandDenied { .. }));
    }

    #[test]
    fn test_validate_pod_state_uppercase_rejected() {
        let err = validate_pod_state("Ready").unwrap_err();
        assert!(matches!(err, BridgeError::CommandDenied { .. }));
    }

    // ── validate_image_ref ────────────────────────────────────────────────────

    #[test]
    fn test_validate_image_ref_simple() {
        assert!(validate_image_ref("ubuntu").is_ok());
    }

    #[test]
    fn test_validate_image_ref_full() {
        assert!(validate_image_ref("registry.io/myorg/myimage:v1.2.3@sha256:abc123").is_ok());
    }

    #[test]
    fn test_validate_image_ref_empty_rejected() {
        assert!(validate_image_ref("").is_err());
    }

    #[test]
    fn test_validate_image_ref_flag_like_rejected() {
        assert!(validate_image_ref("-myimage").is_err());
    }

    #[test]
    fn test_validate_image_ref_shell_chars_rejected() {
        assert!(validate_image_ref("ubuntu;rm -rf /").is_err());
    }

    // ── validate_inspect_kind ─────────────────────────────────────────────────

    #[test]
    fn test_validate_inspect_kind_container() {
        assert!(validate_inspect_kind("container").is_ok());
    }

    #[test]
    fn test_validate_inspect_kind_pod() {
        assert!(validate_inspect_kind("pod").is_ok());
    }

    #[test]
    fn test_validate_inspect_kind_image() {
        assert!(validate_inspect_kind("image").is_ok());
    }

    #[test]
    fn test_validate_inspect_kind_invalid_rejected() {
        let err = validate_inspect_kind("network").unwrap_err();
        assert!(matches!(err, BridgeError::CommandDenied { .. }));
    }

    // ── build_ps_command ──────────────────────────────────────────────────────

    #[test]
    fn test_build_ps_command_defaults() {
        let cmd =
            CrictlCommandBuilder::build_ps_command(Some("crictl"), false, None, None, None, None);
        assert!(cmd.contains("crictl ps"), "cmd: {cmd}");
        assert!(cmd.contains("-o 'json'"), "cmd: {cmd}");
        assert!(!cmd.contains("-a"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_ps_command_all_flag() {
        let cmd =
            CrictlCommandBuilder::build_ps_command(Some("crictl"), true, None, None, None, None);
        assert!(cmd.contains("crictl ps -a"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_ps_command_with_state_filter() {
        let cmd = CrictlCommandBuilder::build_ps_command(
            Some("crictl"),
            false,
            Some("running"),
            None,
            None,
            None,
        );
        assert!(cmd.contains("--state 'running'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_ps_command_with_name_filter() {
        let cmd = CrictlCommandBuilder::build_ps_command(
            Some("crictl"),
            false,
            None,
            Some("my-app"),
            None,
            None,
        );
        assert!(cmd.contains("--name 'my-app'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_ps_command_with_label_filter() {
        let cmd = CrictlCommandBuilder::build_ps_command(
            Some("crictl"),
            false,
            None,
            None,
            Some("app=frontend"),
            None,
        );
        assert!(cmd.contains("--label 'app=frontend'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_ps_command_all_filters() {
        let cmd = CrictlCommandBuilder::build_ps_command(
            Some("crictl"),
            true,
            Some("running"),
            Some("nginx"),
            Some("env=prod"),
            Some("table"),
        );
        assert!(cmd.contains("crictl ps -a"), "cmd: {cmd}");
        assert!(cmd.contains("--state 'running'"), "cmd: {cmd}");
        assert!(cmd.contains("--name 'nginx'"), "cmd: {cmd}");
        assert!(cmd.contains("--label 'env=prod'"), "cmd: {cmd}");
        assert!(cmd.contains("-o 'table'"), "cmd: {cmd}");
    }
}
