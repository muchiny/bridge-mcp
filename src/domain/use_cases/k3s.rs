//! K3s Command Builder
//!
//! Builds k3s lifecycle commands for remote execution: etcd snapshots,
//! node status checks, kernel config validation, containerd image management,
//! and kubeconfig retrieval.

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

/// Generate the k3s detection prefix.
///
/// If `k3s_bin` is supplied and valid, uses it verbatim with a trailing space.
/// Otherwise auto-detects `k3s` via a subshell expression.
#[must_use]
pub fn k3s_detect_prefix(k3s_bin: Option<&str>) -> String {
    if let Some(bin) = k3s_bin
        && is_valid_binary_path(bin)
    {
        return format!("{bin} ");
    }
    "$(if command -v k3s &>/dev/null; then echo k3s; \
     else echo 'k3s not installed on host' >&2; echo false; fi) "
        .to_string()
}

/// Validate an etcd snapshot name.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] if:
/// - empty
/// - contains `/`
/// - starts with `-`
/// - longer than 253 chars
/// - contains characters outside `[A-Za-z0-9._-]`
pub fn validate_snapshot_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "snapshot name must not be empty".to_string(),
        });
    }
    if name.len() > 253 {
        return Err(BridgeError::CommandDenied {
            reason: "snapshot name must be at most 253 characters".to_string(),
        });
    }
    if name.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("snapshot name must not start with '-': {name}"),
        });
    }
    if name.contains('/') {
        return Err(BridgeError::CommandDenied {
            reason: format!("snapshot name must not contain '/': {name}"),
        });
    }
    if !name
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("snapshot name contains disallowed characters: {name}"),
        });
    }
    Ok(())
}

/// Validate an absolute filesystem path.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] if:
/// - empty
/// - does not start with `/`
/// - starts with `-`
/// - contains `..` path segments
/// - contains characters outside `[A-Za-z0-9._/-]`
pub fn validate_path(path: &str) -> Result<()> {
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
    if path.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("path must not start with '-': {path}"),
        });
    }
    // Reject any `..` path segment
    for segment in path.split('/') {
        if segment == ".." {
            return Err(BridgeError::CommandDenied {
                reason: format!("path must not contain '..' segments: {path}"),
            });
        }
    }
    if !path
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '/' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("path contains disallowed characters: {path}"),
        });
    }
    Ok(())
}

/// Validate a server IP or hostname for use in kubeconfig sed replacement.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] if:
/// - starts with `-`
/// - longer than 253 chars
/// - contains characters outside `[A-Za-z0-9.-]`
/// - contains `/` or shell metacharacters
pub fn validate_server_ip(ip: &str) -> Result<()> {
    if ip.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "server_ip must not be empty".to_string(),
        });
    }
    if ip.len() > 253 {
        return Err(BridgeError::CommandDenied {
            reason: "server_ip must be at most 253 characters".to_string(),
        });
    }
    if ip.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("server_ip must not start with '-': {ip}"),
        });
    }
    if !ip
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("server_ip contains disallowed characters: {ip}"),
        });
    }
    Ok(())
}

/// Validate a `ctr images` action.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] if `action` is not one of
/// `ls`, `list`, or `import`.
pub fn validate_ctr_action(action: &str) -> Result<()> {
    match action {
        "ls" | "list" | "import" => Ok(()),
        _ => Err(BridgeError::CommandDenied {
            reason: format!("invalid ctr action '{action}': must be one of 'ls', 'list', 'import'"),
        }),
    }
}

/// Allowed basenames for k3s lifecycle scripts.
const ALLOWED_K3S_SCRIPTS: &[&str] = &[
    "k3s-killall.sh",
    "k3s-uninstall.sh",
    "k3s-agent-uninstall.sh",
];

/// Validate a k3s uninstall/killall script path.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] if:
/// - not an absolute path
/// - basename is not one of the allowed scripts
/// - contains `..` segments, leading `-`, or disallowed characters
pub fn validate_script_path(p: &str) -> Result<()> {
    if p.is_empty() || !p.starts_with('/') {
        return Err(BridgeError::CommandDenied {
            reason: format!("script path must be absolute: {p}"),
        });
    }
    if p.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("script path must not start with '-': {p}"),
        });
    }
    for segment in p.split('/') {
        if segment == ".." {
            return Err(BridgeError::CommandDenied {
                reason: format!("script path must not contain '..' segments: {p}"),
            });
        }
    }
    if !p
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '/' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("script path contains disallowed characters: {p}"),
        });
    }
    let basename = p.split('/').next_back().unwrap_or("");
    if !ALLOWED_K3S_SCRIPTS.contains(&basename) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "script basename '{basename}' is not allowed; must be one of: {}",
                ALLOWED_K3S_SCRIPTS.join(", ")
            ),
        });
    }
    Ok(())
}

/// Validate a k3s certificate service name.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] if `svc` is not in the allowlist.
pub fn validate_cert_service(svc: &str) -> Result<()> {
    const ALLOWED: &[&str] = &[
        "admin",
        "api-server",
        "controller-manager",
        "scheduler",
        "k3s-controller",
        "k3s-server",
        "cloud-controller",
        "etcd",
        "auth-proxy",
        "kubelet",
        "kube-proxy",
        "k3s-server-load-balancer",
    ];
    if ALLOWED.contains(&svc) {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "invalid cert service '{svc}': must be one of: {}",
                ALLOWED.join(", ")
            ),
        })
    }
}

/// Validate a k3s version string.
///
/// Accepts pinned k3s tags (`v1.30.2+k3s1`) or plain semver (`v1.30.2`).
/// Rejects empty strings, channel names (`latest`, `stable`, `testing`),
/// leading `-`, and any character outside `[A-Za-z0-9.+-]`.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] for any invalid input.
pub fn validate_k3s_version(v: &str) -> Result<()> {
    if v.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "version must not be empty".to_string(),
        });
    }
    if v.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!("version must not start with '-': {v}"),
        });
    }
    // Reject unpinned channels used as version (prevent surprise upgrades)
    if matches!(v, "latest" | "stable" | "testing") {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "version '{v}' is a channel name, not a pinned version; \
                 use validate_channel instead"
            ),
        });
    }
    // Charset: [A-Za-z0-9.+-] only
    if !v
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '+' | '-'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!("version contains disallowed characters: {v}"),
        });
    }
    // Must look like a version (contain at least one digit and one dot)
    if !v.contains('.') || !v.chars().any(|c| c.is_ascii_digit()) {
        return Err(BridgeError::CommandDenied {
            reason: format!("version does not look like a version string: {v}"),
        });
    }
    Ok(())
}

/// Validate a k3s release channel name.
///
/// Only `stable`, `latest`, and `testing` are accepted.
///
/// # Errors
/// Returns [`BridgeError::CommandDenied`] for any other value.
pub fn validate_channel(c: &str) -> Result<()> {
    match c {
        "stable" | "latest" | "testing" => Ok(()),
        _ => Err(BridgeError::CommandDenied {
            reason: format!("invalid channel '{c}': must be one of 'stable', 'latest', 'testing'"),
        }),
    }
}

/// Builds k3s CLI commands.
pub struct K3sCommandBuilder;

impl K3sCommandBuilder {
    /// Build an `etcd-snapshot save` command.
    ///
    /// # Parameters
    /// - `k3s_bin` — explicit k3s binary path, or `None` for auto-detect
    /// - `name` — optional snapshot name (pre-validated)
    /// - `dir` — optional output directory (pre-validated)
    #[must_use]
    pub fn build_etcd_snapshot_save_command(
        k3s_bin: Option<&str>,
        name: Option<&str>,
        dir: Option<&str>,
    ) -> String {
        use std::fmt::Write;
        let prefix = k3s_detect_prefix(k3s_bin);
        let mut cmd = format!("sudo {prefix}etcd-snapshot save");
        if let Some(n) = name {
            let _ = write!(cmd, " --name {}", shell_escape(n));
        }
        if let Some(d) = dir {
            let _ = write!(cmd, " --dir {}", shell_escape(d));
        }
        cmd
    }

    /// Build an `etcd-snapshot ls -o json` command.
    ///
    /// # Parameters
    /// - `k3s_bin` — explicit k3s binary path, or `None` for auto-detect
    /// - `dir` — optional snapshot directory to list (pre-validated)
    #[must_use]
    pub fn build_etcd_snapshot_list_command(k3s_bin: Option<&str>, dir: Option<&str>) -> String {
        use std::fmt::Write;
        let prefix = k3s_detect_prefix(k3s_bin);
        let mut cmd = format!("sudo {prefix}etcd-snapshot ls -o json");
        if let Some(d) = dir {
            let _ = write!(cmd, " --dir {}", shell_escape(d));
        }
        cmd
    }

    /// Build an etcd snapshot restore command (`k3s server --cluster-reset ...`).
    ///
    /// # Parameters
    /// - `k3s_bin` — explicit k3s binary path, or `None` for auto-detect
    /// - `snapshot_path` — absolute path to the snapshot file (pre-validated)
    ///
    /// # Errors
    /// Returns `CommandDenied` if `snapshot_path` fails validation.
    pub fn build_etcd_snapshot_restore_command(
        k3s_bin: Option<&str>,
        snapshot_path: &str,
    ) -> Result<String> {
        validate_path(snapshot_path)?;
        let prefix = k3s_detect_prefix(k3s_bin);
        Ok(format!(
            "sudo {prefix}server --cluster-reset --cluster-reset-restore-path={}",
            shell_escape(snapshot_path)
        ))
    }

    /// Build the etcd status composite command (single pipeline string).
    ///
    /// Checks datastore config, latest snapshot, and `/healthz/etcd`.
    #[must_use]
    pub fn build_etcd_status_command(k3s_bin: Option<&str>, kubectl_bin: Option<&str>) -> String {
        let k3s_prefix = k3s_detect_prefix(k3s_bin);
        let kubectl_prefix =
            crate::domain::use_cases::kubernetes::kubectl_detect_prefix(kubectl_bin);
        format!(
            "echo '== datastore ==' && \
(sudo grep -E 'cluster-init|datastore-endpoint|disable-etcd|server:' \
/etc/rancher/k3s/config.yaml 2>/dev/null || echo 'embedded-etcd (default)'); \
echo '== latest snapshot =='; \
sudo {k3s_prefix}etcd-snapshot ls -o json 2>/dev/null | \
(command -v jq >/dev/null 2>&1 && \
jq -r 'if type==\"array\" then \
(sort_by(.metadata.creationTimestamp // .createdAt) | last | \
\"name=\\(.metadata.name // .name) \
created=\\(.metadata.creationTimestamp // .createdAt) \
size=\\(.size)\") else . end' || tail -n 3); \
echo '== /healthz/etcd =='; \
{kubectl_prefix}get --raw='/healthz/etcd' 2>&1 || echo 'healthz/etcd unavailable'"
        )
    }

    /// Build the k3s cluster status composite command (single pipeline string).
    ///
    /// Checks systemd unit state, node list, readyz, and containerd version.
    #[must_use]
    pub fn build_k3s_status_command(kubectl_bin: Option<&str>) -> String {
        let kubectl_prefix =
            crate::domain::use_cases::kubernetes::kubectl_detect_prefix(kubectl_bin);
        format!(
            "echo '== systemd ==' && \
(systemctl is-active k3s 2>/dev/null || \
systemctl is-active k3s-agent 2>/dev/null || echo inactive); \
systemctl show -p ActiveState,SubState,ExecMainStartTimestamp k3s 2>/dev/null; \
echo '== nodes =='; \
{kubectl_prefix}get nodes \
-o custom-columns='NAME:.metadata.name,STATUS:.status.conditions[-1].type,\
VERSION:.status.nodeInfo.kubeletVersion' \
--no-headers 2>&1 | head -n 50; \
echo '== readyz =='; \
{kubectl_prefix}get --raw='/readyz?verbose' 2>&1 | tail -n 20 || \
echo 'readyz unavailable'; \
echo '== containerd =='; \
(sudo k3s ctr version 2>/dev/null | head -n 4 || \
echo 'containerd/k3s ctr unavailable')"
        )
    }

    /// Build a `k3s check-config` command.
    #[must_use]
    pub fn build_check_config_command(k3s_bin: Option<&str>) -> String {
        let prefix = k3s_detect_prefix(k3s_bin);
        format!("sudo {prefix}check-config")
    }

    /// Build a `ctr images` command.
    ///
    /// # Parameters
    /// - `k3s_bin` — explicit k3s binary path, or `None` for auto-detect
    /// - `action` — one of `ls`, `list`, `import` (pre-validated)
    /// - `tarball` — optional tarball path, required for `import` (pre-validated)
    ///
    /// # Errors
    /// Returns `CommandDenied` if action is `import` and `tarball` is `None`.
    pub fn build_ctr_images_command(
        k3s_bin: Option<&str>,
        action: &str,
        tarball: Option<&str>,
    ) -> Result<String> {
        use std::fmt::Write;
        if action == "import" && tarball.is_none() {
            return Err(BridgeError::CommandDenied {
                reason: "action 'import' requires a tarball path".to_string(),
            });
        }
        let prefix = k3s_detect_prefix(k3s_bin);
        let mut cmd = format!("sudo {prefix}ctr images {}", shell_escape(action));
        if let Some(t) = tarball {
            let _ = write!(cmd, " {}", shell_escape(t));
        }
        Ok(cmd)
    }

    /// Build a kubeconfig retrieval command.
    ///
    /// If `server_ip` is provided, rewrites the `127.0.0.1`/`0.0.0.0` server
    /// address in the yaml output with the given IP (validated, no shell
    /// metachars, interpolated directly after `#` sed delimiter).
    ///
    /// # Parameters
    /// - `path` — optional path to the kubeconfig file (pre-validated)
    /// - `server_ip` — optional IP/hostname to substitute (pre-validated)
    #[must_use]
    pub fn build_kubeconfig_get_command(path: Option<&str>, server_ip: Option<&str>) -> String {
        let file = path.unwrap_or("/etc/rancher/k3s/k3s.yaml");
        let cat = format!("sudo cat {}", shell_escape(file));
        if let Some(ip) = server_ip {
            // server_ip is strictly validated — charset [A-Za-z0-9.-], no slashes,
            // no shell metacharacters — safe to interpolate directly after `#` delimiter.
            format!(
                "{cat} | sed -E \
's#server: https://127\\.0\\.0\\.1:6443#server: https://{ip}:6443#; \
s#server: https://0\\.0\\.0\\.0:6443#server: https://{ip}:6443#'"
            )
        } else {
            cat
        }
    }

    /// Build a k3s config file retrieval command.
    ///
    /// Reads `/etc/rancher/k3s/config.yaml` and any `config.yaml.d/*.yaml`
    /// drop-ins.  If `config_path` is provided, it replaces the primary path.
    ///
    /// # Parameters
    /// - `config_path` — optional override for the primary config path
    ///   (pre-validated with [`validate_path`]).
    #[must_use]
    pub fn build_config_get_command(config_path: Option<&str>) -> String {
        let primary = if let Some(p) = config_path {
            shell_escape(p)
        } else {
            "/etc/rancher/k3s/config.yaml".to_string()
        };
        format!(
            "for f in {primary} /etc/rancher/k3s/config.yaml.d/*.yaml; \
do [ -f \"$f\" ] && echo \"== $f ==\" && sudo cat \"$f\"; done 2>/dev/null"
        )
    }

    /// Build a `certificate rotate` command.
    ///
    /// Appends `--service <svc>` for each entry in `service` (each pre-validated
    /// by the caller via [`validate_cert_service`]).
    #[must_use]
    pub fn build_cert_rotate_command(k3s_bin: Option<&str>, service: Option<&[String]>) -> String {
        use std::fmt::Write;
        let prefix = k3s_detect_prefix(k3s_bin);
        let mut cmd = format!("sudo {prefix}certificate rotate");
        if let Some(services) = service {
            for svc in services {
                let _ = write!(cmd, " --service {}", shell_escape(svc));
            }
        }
        cmd
    }

    /// Build a `k3s-killall.sh` execution command.
    ///
    /// Uses `/usr/local/bin/k3s-killall.sh` by default. If `script_path` is
    /// supplied, the caller MUST have already validated it via
    /// [`validate_script_path`].
    #[must_use]
    pub fn build_killall_command(script_path: Option<&str>) -> String {
        let path = script_path.unwrap_or("/usr/local/bin/k3s-killall.sh");
        format!("sudo {}", shell_escape(path))
    }

    /// Build a k3s uninstall command (server or agent).
    ///
    /// # Errors
    /// Returns `CommandDenied` if `script_path` validation fails.
    pub fn build_uninstall_command(agent: bool, script_path: Option<&str>) -> Result<String> {
        let default_path = if agent {
            "/usr/local/bin/k3s-agent-uninstall.sh"
        } else {
            "/usr/local/bin/k3s-uninstall.sh"
        };
        let path = if let Some(p) = script_path {
            validate_script_path(p)?;
            p
        } else {
            default_path
        };
        Ok(format!("sudo {}", shell_escape(path)))
    }

    /// Build a k3s upgrade command using the official installer.
    ///
    /// The installer URL `https://get.k3s.io` is a fixed literal — never
    /// interpolated. Only `version` and optionally `channel` are injected,
    /// both shell-escaped after validation.
    ///
    /// # Errors
    /// Returns `CommandDenied` if `version` or `channel` fails validation.
    pub fn build_upgrade_command(version: &str, channel: Option<&str>) -> Result<String> {
        use std::fmt::Write;
        validate_k3s_version(version)?;
        if let Some(c) = channel {
            validate_channel(c)?;
        }
        let mut cmd = format!(
            "curl -sfL https://get.k3s.io | sudo INSTALL_K3S_VERSION={}",
            shell_escape(version)
        );
        if let Some(c) = channel {
            let _ = write!(cmd, " INSTALL_K3S_CHANNEL={}", shell_escape(c));
        }
        cmd.push_str(" sh -");
        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── k3s_detect_prefix ─────────────────────────────────────────────────────

    #[test]
    fn test_detect_prefix_explicit_bin() {
        let prefix = k3s_detect_prefix(Some("k3s"));
        assert_eq!(prefix, "k3s ");
    }

    #[test]
    fn test_detect_prefix_explicit_full_path() {
        let prefix = k3s_detect_prefix(Some("/usr/local/bin/k3s"));
        assert_eq!(prefix, "/usr/local/bin/k3s ");
    }

    #[test]
    fn test_detect_prefix_none_uses_subshell() {
        let prefix = k3s_detect_prefix(None);
        assert!(prefix.contains("command -v k3s"), "prefix: {prefix}");
        assert!(prefix.contains("&>/dev/null"), "prefix: {prefix}");
    }

    #[test]
    fn test_detect_prefix_invalid_bin_falls_back_to_subshell() {
        let prefix = k3s_detect_prefix(Some("k3s; rm -rf /"));
        assert!(
            prefix.contains("command -v k3s"),
            "invalid bin should fall back to auto-detect: {prefix}"
        );
    }

    // ── validate_snapshot_name ────────────────────────────────────────────────

    #[test]
    fn test_validate_snapshot_name_valid() {
        assert!(validate_snapshot_name("my-snapshot.v1").is_ok());
    }

    #[test]
    fn test_validate_snapshot_name_empty_rejected() {
        assert!(matches!(
            validate_snapshot_name("").unwrap_err(),
            BridgeError::CommandDenied { .. }
        ));
    }

    #[test]
    fn test_validate_snapshot_name_leading_dash_rejected() {
        assert!(validate_snapshot_name("-snap").is_err());
    }

    #[test]
    fn test_validate_snapshot_name_slash_rejected() {
        assert!(validate_snapshot_name("snap/bad").is_err());
    }

    #[test]
    fn test_validate_snapshot_name_shell_chars_rejected() {
        assert!(validate_snapshot_name("snap$(id)").is_err());
    }

    // ── validate_path ─────────────────────────────────────────────────────────

    #[test]
    fn test_validate_path_valid() {
        assert!(validate_path("/var/lib/rancher/k3s/snapshots").is_ok());
    }

    #[test]
    fn test_validate_path_not_absolute_rejected() {
        assert!(validate_path("relative/path").is_err());
    }

    #[test]
    fn test_validate_path_dotdot_rejected() {
        assert!(validate_path("/etc/../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_path_empty_rejected() {
        assert!(validate_path("").is_err());
    }

    #[test]
    fn test_validate_path_shell_chars_rejected() {
        assert!(validate_path("/tmp/$(id)").is_err());
    }

    // ── validate_server_ip ────────────────────────────────────────────────────

    #[test]
    fn test_validate_server_ip_valid_ipv4() {
        assert!(validate_server_ip("192.168.1.100").is_ok());
    }

    #[test]
    fn test_validate_server_ip_valid_hostname() {
        assert!(validate_server_ip("k3s-server.local").is_ok());
    }

    #[test]
    fn test_validate_server_ip_slash_rejected() {
        assert!(validate_server_ip("192.168.1.1/24").is_err());
    }

    #[test]
    fn test_validate_server_ip_leading_dash_rejected() {
        assert!(validate_server_ip("-k3s").is_err());
    }

    #[test]
    fn test_validate_server_ip_shell_chars_rejected() {
        assert!(validate_server_ip("127.0.0.1;rm").is_err());
    }

    // ── validate_ctr_action ───────────────────────────────────────────────────

    #[test]
    fn test_validate_ctr_action_ls() {
        assert!(validate_ctr_action("ls").is_ok());
    }

    #[test]
    fn test_validate_ctr_action_list() {
        assert!(validate_ctr_action("list").is_ok());
    }

    #[test]
    fn test_validate_ctr_action_import() {
        assert!(validate_ctr_action("import").is_ok());
    }

    #[test]
    fn test_validate_ctr_action_invalid_rejected() {
        assert!(validate_ctr_action("pull").is_err());
    }

    // ── validate_script_path ──────────────────────────────────────────────────

    #[test]
    fn test_validate_script_path_killall() {
        assert!(validate_script_path("/usr/local/bin/k3s-killall.sh").is_ok());
    }

    #[test]
    fn test_validate_script_path_uninstall() {
        assert!(validate_script_path("/usr/local/bin/k3s-uninstall.sh").is_ok());
    }

    #[test]
    fn test_validate_script_path_agent_uninstall() {
        assert!(validate_script_path("/usr/local/bin/k3s-agent-uninstall.sh").is_ok());
    }

    #[test]
    fn test_validate_script_path_not_absolute_rejected() {
        assert!(validate_script_path("k3s-uninstall.sh").is_err());
    }

    #[test]
    fn test_validate_script_path_wrong_basename_rejected() {
        assert!(validate_script_path("/usr/local/bin/custom.sh").is_err());
    }

    #[test]
    fn test_validate_script_path_dotdot_rejected() {
        assert!(validate_script_path("/usr/local/../bin/k3s-uninstall.sh").is_err());
    }

    // ── validate_cert_service ─────────────────────────────────────────────────

    #[test]
    fn test_validate_cert_service_etcd() {
        assert!(validate_cert_service("etcd").is_ok());
    }

    #[test]
    fn test_validate_cert_service_api_server() {
        assert!(validate_cert_service("api-server").is_ok());
    }

    #[test]
    fn test_validate_cert_service_invalid_rejected() {
        assert!(validate_cert_service("unknown-service").is_err());
    }

    // ── build_etcd_snapshot_save_command ──────────────────────────────────────

    #[test]
    fn test_build_etcd_snapshot_save_minimal() {
        let cmd = K3sCommandBuilder::build_etcd_snapshot_save_command(Some("k3s"), None, None);
        assert!(cmd.contains("sudo k3s etcd-snapshot save"), "cmd: {cmd}");
        assert!(!cmd.contains("--name"), "cmd: {cmd}");
        assert!(!cmd.contains("--dir"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_etcd_snapshot_save_with_name_and_dir() {
        let cmd = K3sCommandBuilder::build_etcd_snapshot_save_command(
            Some("k3s"),
            Some("my-snapshot"),
            Some("/var/lib/rancher/k3s/server/db/snapshots"),
        );
        assert!(cmd.contains("--name 'my-snapshot'"), "cmd: {cmd}");
        assert!(
            cmd.contains("--dir '/var/lib/rancher/k3s/server/db/snapshots'"),
            "cmd: {cmd}"
        );
    }

    // ── build_etcd_snapshot_list_command ──────────────────────────────────────

    #[test]
    fn test_build_etcd_snapshot_list_minimal() {
        let cmd = K3sCommandBuilder::build_etcd_snapshot_list_command(Some("k3s"), None);
        assert!(
            cmd.contains("sudo k3s etcd-snapshot ls -o json"),
            "cmd: {cmd}"
        );
        assert!(!cmd.contains("--dir"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_etcd_snapshot_list_with_dir() {
        let cmd = K3sCommandBuilder::build_etcd_snapshot_list_command(
            Some("k3s"),
            Some("/var/lib/rancher/k3s/server/db/snapshots"),
        );
        assert!(
            cmd.contains("--dir '/var/lib/rancher/k3s/server/db/snapshots'"),
            "cmd: {cmd}"
        );
    }

    // ── build_etcd_snapshot_restore_command ───────────────────────────────────

    #[test]
    fn test_build_etcd_snapshot_restore_valid() {
        let cmd = K3sCommandBuilder::build_etcd_snapshot_restore_command(
            Some("k3s"),
            "/var/lib/rancher/k3s/server/db/snapshots/my-snap.db",
        );
        assert!(cmd.is_ok(), "should build restore command");
        let cmd = cmd.unwrap();
        assert!(cmd.contains("--cluster-reset"), "cmd: {cmd}");
        assert!(cmd.contains("--cluster-reset-restore-path="), "cmd: {cmd}");
    }

    #[test]
    fn test_build_etcd_snapshot_restore_invalid_path() {
        let result =
            K3sCommandBuilder::build_etcd_snapshot_restore_command(Some("k3s"), "relative/path");
        assert!(result.is_err());
    }

    // ── build_etcd_status_command ─────────────────────────────────────────────

    #[test]
    fn test_build_etcd_status_contains_sections() {
        let cmd = K3sCommandBuilder::build_etcd_status_command(Some("k3s"), Some("kubectl"));
        assert!(cmd.contains("== datastore =="), "cmd: {cmd}");
        assert!(cmd.contains("== latest snapshot =="), "cmd: {cmd}");
        assert!(cmd.contains("== /healthz/etcd =="), "cmd: {cmd}");
        assert!(
            cmd.contains("sudo k3s etcd-snapshot ls -o json"),
            "cmd: {cmd}"
        );
        assert!(cmd.contains("kubectl get --raw="), "cmd: {cmd}");
    }

    #[test]
    fn test_build_etcd_status_uses_kubectl_prefix() {
        let cmd =
            K3sCommandBuilder::build_etcd_status_command(Some("k3s"), Some("/usr/bin/kubectl"));
        assert!(cmd.contains("/usr/bin/kubectl get --raw="), "cmd: {cmd}");
    }

    // ── build_k3s_status_command ──────────────────────────────────────────────

    #[test]
    fn test_build_k3s_status_contains_sections() {
        let cmd = K3sCommandBuilder::build_k3s_status_command(Some("kubectl"));
        assert!(cmd.contains("== systemd =="), "cmd: {cmd}");
        assert!(cmd.contains("== nodes =="), "cmd: {cmd}");
        assert!(cmd.contains("== readyz =="), "cmd: {cmd}");
        assert!(cmd.contains("== containerd =="), "cmd: {cmd}");
        assert!(cmd.contains("kubectl get nodes"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_k3s_status_uses_kubectl_prefix() {
        let cmd = K3sCommandBuilder::build_k3s_status_command(Some("/usr/bin/kubectl"));
        assert!(cmd.contains("/usr/bin/kubectl get nodes"), "cmd: {cmd}");
    }

    // ── build_check_config_command ────────────────────────────────────────────

    #[test]
    fn test_build_check_config_command() {
        let cmd = K3sCommandBuilder::build_check_config_command(Some("k3s"));
        assert_eq!(cmd, "sudo k3s check-config");
    }

    #[test]
    fn test_build_check_config_command_custom_bin() {
        let cmd = K3sCommandBuilder::build_check_config_command(Some("/usr/local/bin/k3s"));
        assert_eq!(cmd, "sudo /usr/local/bin/k3s check-config");
    }

    // ── build_ctr_images_command ──────────────────────────────────────────────

    #[test]
    fn test_build_ctr_images_ls() {
        let cmd = K3sCommandBuilder::build_ctr_images_command(Some("k3s"), "ls", None);
        assert!(cmd.is_ok(), "ls should not require tarball");
        let cmd = cmd.unwrap();
        assert!(cmd.contains("sudo k3s ctr images 'ls'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_ctr_images_import_without_tarball_rejected() {
        let result = K3sCommandBuilder::build_ctr_images_command(Some("k3s"), "import", None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BridgeError::CommandDenied { .. }
        ));
    }

    #[test]
    fn test_build_ctr_images_import_with_tarball() {
        let cmd = K3sCommandBuilder::build_ctr_images_command(
            Some("k3s"),
            "import",
            Some("/tmp/my-image.tar"),
        );
        assert!(cmd.is_ok(), "import with tarball should succeed");
        let cmd = cmd.unwrap();
        assert!(cmd.contains("'import'"), "cmd: {cmd}");
        assert!(cmd.contains("'/tmp/my-image.tar'"), "cmd: {cmd}");
    }

    // ── build_kubeconfig_get_command ──────────────────────────────────────────

    #[test]
    fn test_build_kubeconfig_get_default_path() {
        let cmd = K3sCommandBuilder::build_kubeconfig_get_command(None, None);
        assert!(
            cmd.contains("sudo cat '/etc/rancher/k3s/k3s.yaml'"),
            "cmd: {cmd}"
        );
        assert!(!cmd.contains("sed"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_kubeconfig_get_with_server_ip() {
        let cmd = K3sCommandBuilder::build_kubeconfig_get_command(None, Some("192.168.1.100"));
        assert!(cmd.contains("sed"), "cmd: {cmd}");
        assert!(cmd.contains("192.168.1.100:6443"), "cmd: {cmd}");
        // sed pattern uses escaped dots — check for the pattern fragment
        assert!(
            cmd.contains("127"),
            "should contain 127.x.x.x pattern in sed: {cmd}"
        );
    }

    #[test]
    fn test_build_kubeconfig_get_custom_path() {
        let cmd = K3sCommandBuilder::build_kubeconfig_get_command(Some("/root/.kube/config"), None);
        assert!(cmd.contains("sudo cat '/root/.kube/config'"), "cmd: {cmd}");
    }

    // ── build_config_get_command ──────────────────────────────────────────────

    #[test]
    fn test_build_config_get_default() {
        let cmd = K3sCommandBuilder::build_config_get_command(None);
        assert!(cmd.contains("/etc/rancher/k3s/config.yaml"), "cmd: {cmd}");
        assert!(cmd.contains("config.yaml.d/*.yaml"), "cmd: {cmd}");
        assert!(cmd.contains("for f in"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_config_get_custom_path() {
        let cmd = K3sCommandBuilder::build_config_get_command(Some(
            "/etc/rancher/k3s/config-custom.yaml",
        ));
        assert!(
            cmd.contains("'/etc/rancher/k3s/config-custom.yaml'"),
            "cmd: {cmd}"
        );
    }

    // ── validate_k3s_version ────────────────────────────────────────────────

    #[test]
    fn test_validate_k3s_version_valid_k3s_tag() {
        assert!(validate_k3s_version("v1.30.2+k3s1").is_ok());
    }

    #[test]
    fn test_validate_k3s_version_valid_plain_semver() {
        assert!(validate_k3s_version("v1.30.2").is_ok());
    }

    #[test]
    fn test_validate_k3s_version_empty_rejected() {
        assert!(validate_k3s_version("").is_err());
    }

    #[test]
    fn test_validate_k3s_version_leading_dash_rejected() {
        assert!(validate_k3s_version("-v1.30.2").is_err());
    }

    #[test]
    fn test_validate_k3s_version_channel_names_rejected() {
        assert!(validate_k3s_version("latest").is_err());
        assert!(validate_k3s_version("stable").is_err());
        assert!(validate_k3s_version("testing").is_err());
    }

    #[test]
    fn test_validate_k3s_version_no_dot_rejected() {
        assert!(validate_k3s_version("v130").is_err());
    }

    #[test]
    fn test_validate_k3s_version_disallowed_chars_rejected() {
        assert!(validate_k3s_version("v1.30.2;rm -rf /").is_err());
    }

    // ── validate_channel ────────────────────────────────────────────────────

    #[test]
    fn test_validate_channel_stable_ok() {
        assert!(validate_channel("stable").is_ok());
    }

    #[test]
    fn test_validate_channel_latest_ok() {
        assert!(validate_channel("latest").is_ok());
    }

    #[test]
    fn test_validate_channel_testing_ok() {
        assert!(validate_channel("testing").is_ok());
    }

    #[test]
    fn test_validate_channel_invalid_rejected() {
        assert!(validate_channel("edge").is_err());
        assert!(validate_channel("").is_err());
    }

    // ── build_cert_rotate_command ────────────────────────────────────────────

    #[test]
    fn test_build_cert_rotate_no_service() {
        let cmd = K3sCommandBuilder::build_cert_rotate_command(Some("k3s"), None);
        assert!(cmd.contains("sudo k3s certificate rotate"), "cmd: {cmd}");
        assert!(!cmd.contains("--service"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_cert_rotate_with_services() {
        let services = vec!["etcd".to_string(), "api-server".to_string()];
        let cmd = K3sCommandBuilder::build_cert_rotate_command(Some("k3s"), Some(&services));
        assert!(cmd.contains("--service 'etcd'"), "cmd: {cmd}");
        assert!(cmd.contains("--service 'api-server'"), "cmd: {cmd}");
    }

    // ── build_killall_command ────────────────────────────────────────────────

    #[test]
    fn test_build_killall_default_path() {
        let cmd = K3sCommandBuilder::build_killall_command(None);
        assert!(cmd.contains("/usr/local/bin/k3s-killall.sh"), "cmd: {cmd}");
        assert!(cmd.starts_with("sudo "), "cmd: {cmd}");
    }

    #[test]
    fn test_build_killall_custom_path() {
        let cmd = K3sCommandBuilder::build_killall_command(Some("/opt/k3s/k3s-killall.sh"));
        assert!(cmd.contains("/opt/k3s/k3s-killall.sh"), "cmd: {cmd}");
    }

    // ── build_uninstall_command ──────────────────────────────────────────────

    #[test]
    fn test_build_uninstall_server() {
        let cmd = K3sCommandBuilder::build_uninstall_command(false, None).unwrap();
        assert!(cmd.contains("k3s-uninstall.sh"), "cmd: {cmd}");
        assert!(!cmd.contains("agent"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_uninstall_agent() {
        let cmd = K3sCommandBuilder::build_uninstall_command(true, None).unwrap();
        assert!(cmd.contains("k3s-agent-uninstall.sh"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_uninstall_invalid_script_rejected() {
        let result = K3sCommandBuilder::build_uninstall_command(false, Some("/tmp/evil.sh"));
        assert!(result.is_err());
    }

    // ── build_upgrade_command ────────────────────────────────────────────────

    #[test]
    fn test_build_upgrade_k3s_version_tag() {
        let cmd = K3sCommandBuilder::build_upgrade_command("v1.30.2+k3s1", None).unwrap();
        assert!(cmd.contains("https://get.k3s.io"), "cmd: {cmd}");
        assert!(cmd.contains("INSTALL_K3S_VERSION="), "cmd: {cmd}");
        assert!(cmd.contains("v1.30.2"), "cmd: {cmd}");
        assert!(cmd.ends_with("sh -"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_upgrade_with_channel() {
        let cmd = K3sCommandBuilder::build_upgrade_command("v1.30.2+k3s1", Some("stable")).unwrap();
        assert!(cmd.contains("INSTALL_K3S_CHANNEL="), "cmd: {cmd}");
        assert!(cmd.contains("stable"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_upgrade_invalid_version_rejected() {
        let result = K3sCommandBuilder::build_upgrade_command("latest", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_upgrade_invalid_channel_rejected() {
        let result = K3sCommandBuilder::build_upgrade_command("v1.30.2+k3s1", Some("edge"));
        assert!(result.is_err());
    }
}
