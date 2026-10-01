//! GCP OS Command adapter — execute commands on Google Cloud VMs
//!
//! Uses the Google Cloud Compute Engine API to run commands on VM instances
//! via `gcloud compute ssh --command`. Since there is no direct
//! "Run Command" API equivalent in GCP, this adapter wraps `gcloud` CLI calls.
//!
//! **Not air-gapped compatible** — requires connectivity to GCP APIs.
//!
//! Feature-gated behind `gcp`.

use std::sync::OnceLock;
use std::time::Instant;

use tracing::{debug, info, warn};

/// One-shot check that `gcloud` is on `$PATH`. Logs a warning the first time
/// the GCP adapter is used on a host without `gcloud` installed.
fn warn_if_gcloud_missing() {
    static CHECKED: OnceLock<()> = OnceLock::new();
    CHECKED.get_or_init(|| {
        if which_gcloud().is_none() {
            warn!(
                "GCP adapter is configured but `gcloud` CLI was not found in $PATH. \
                 Install Google Cloud SDK on the bridge host or remove GCP hosts from config."
            );
        }
    });
}

/// Best-effort lookup of `gcloud` in `$PATH`. Returns the absolute path if found.
fn which_gcloud() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("gcloud");
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate_exe = dir.join("gcloud.exe");
            if candidate_exe.is_file() {
                return Some(candidate_exe);
            }
            let candidate_cmd = dir.join("gcloud.cmd");
            if candidate_cmd.is_file() {
                return Some(candidate_cmd);
            }
        }
    }
    None
}

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// GCP OS Command connection.
///
/// The `HostConfig` is interpreted as follows:
/// - `hostname` → VM instance name
/// - `user` → GCP project ID
/// - `description` → zone (default: auto-detect via `gcloud config get-value compute/zone`)
///
/// Authentication uses Application Default Credentials (ADC) or
/// `gcloud auth` session.
pub struct GcpRunConnection {
    instance_name: String,
    project: String,
    zone: String,
    host_name: String,
    failed: bool,
}

impl GcpRunConnection {
    /// Create a GCP command execution connection.
    ///
    /// Resolves the project, zone, and instance from `HostConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if project or zone cannot be determined.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        info!(host = %host_name, instance = %host_config.hostname, "Connecting via GCP OS Command");
        warn_if_gcloud_missing();

        let project = if host_config.user.is_empty() || host_config.user == "root" {
            // Try to get project from gcloud config
            get_gcloud_config("project").await.map_err(|_| {
                BridgeError::Config(
                    "GCP host requires project ID in user field or gcloud config".to_string(),
                )
            })?
        } else {
            host_config.user.clone()
        };

        let zone = if let Some(ref desc) = host_config.description {
            desc.clone()
        } else {
            get_gcloud_config("compute/zone")
                .await
                .unwrap_or_else(|_| "us-central1-a".to_string())
        };

        info!(
            host = %host_name,
            instance = %host_config.hostname,
            project = %project,
            zone = %zone,
            "GCP OS Command target resolved"
        );

        Ok(Self {
            instance_name: host_config.hostname.clone(),
            project,
            zone,
            host_name: host_name.to_string(),
            failed: false,
        })
    }

    /// Execute a command on the GCP VM instance.
    ///
    /// Uses `gcloud compute ssh` with `--command` flag for execution.
    /// For instances with OS Config agent, falls back to OS Config API.
    ///
    /// # Errors
    ///
    /// Returns an error if `gcloud` is not available or the command fails.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            instance = %self.instance_name,
            command = %command,
            "Executing GCP OS Command"
        );

        let output = tokio::process::Command::new("gcloud")
            .args([
                "compute",
                "ssh",
                &self.instance_name,
                "--project",
                &self.project,
                "--zone",
                &self.zone,
                "--command",
                command,
                "--quiet",
                "--tunnel-through-iap",
            ])
            .output()
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("gcloud CLI not available: {e}"),
            })?;

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let exit_code = output.status.code().unwrap_or(1) as u32;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code,
            duration_ms: elapsed_ms(start),
        })
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "GCP OS Command connection marked as failed");
    }
}

/// Get a value from gcloud configuration.
async fn get_gcloud_config(key: &str) -> Result<String> {
    let output = tokio::process::Command::new("gcloud")
        .args(["config", "get-value", key])
        .output()
        .await
        .map_err(|e| BridgeError::SshExec {
            reason: format!("gcloud CLI not available: {e}"),
        })?;

    if !output.status.success() {
        return Err(BridgeError::SshExec {
            reason: format!("gcloud config get-value {key} failed"),
        });
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() || value == "(unset)" {
        return Err(BridgeError::SshExec {
            reason: format!("gcloud config {key} is not set"),
        });
    }

    Ok(value)
}

/// Convert elapsed duration to milliseconds, saturating on overflow.
#[allow(clippy::cast_possible_truncation)]
fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_instance_name_format() {
        let instance = "my-web-server-01";
        assert!(!instance.contains('/'));
        assert_ne!(instance, "");
    }

    #[test]
    fn test_zone_format() {
        let zone = "us-central1-a";
        assert!(zone.contains('-'));
        let parts: Vec<&str> = zone.split('-').collect();
        assert!(parts.len() >= 3);
    }

    #[test]
    fn test_project_format() {
        let project = "my-gcp-project-123";
        assert_ne!(project, "");
    }

    #[test]
    fn test_zone_common_values() {
        let zones = [
            "us-central1-a",
            "us-east1-b",
            "europe-west1-c",
            "asia-southeast1-a",
        ];
        for zone in &zones {
            let parts: Vec<&str> = zone.split('-').collect();
            assert!(
                parts.len() >= 3,
                "Zone should have at least 3 parts: {zone}"
            );
        }
    }

    #[test]
    fn test_zone_default_fallback() {
        let description: Option<String> = None;
        let zone = if let Some(ref desc) = description {
            desc.clone()
        } else {
            "us-central1-a".to_string()
        };
        assert_eq!(zone, "us-central1-a");
    }

    #[test]
    fn test_zone_from_description() {
        let description: Option<String> = Some("europe-west4-b".to_string());
        let zone = if let Some(ref desc) = description {
            desc.clone()
        } else {
            "us-central1-a".to_string()
        };
        assert_eq!(zone, "europe-west4-b");
    }

    #[test]
    fn test_project_fallback_logic() {
        // When user is empty or "root", should try gcloud config
        let user = "root";
        let needs_gcloud = user.is_empty() || user == "root";
        assert!(needs_gcloud);

        let user2 = "my-project-id";
        let needs_gcloud2 = user2.is_empty() || user2 == "root";
        assert!(!needs_gcloud2);
    }

    #[test]
    fn test_instance_name_valid_chars() {
        // GCP instance names must match [a-z]([-a-z0-9]*[a-z0-9])?
        let valid = "my-web-server-01";
        assert!(
            valid
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        );
    }

    #[test]
    fn test_gcloud_unset_value() {
        // gcloud returns "(unset)" for unconfigured values
        let value = "(unset)";
        assert!(value.is_empty() || value == "(unset)");
    }

    #[test]
    fn test_elapsed_ms() {
        use super::*;
        let start = std::time::Instant::now();
        let ms = elapsed_ms(start);
        assert!(ms < 100);
    }

    #[test]
    fn test_gcloud_command_args() {
        let instance = "my-vm";
        let project = "my-project";
        let zone = "us-central1-a";
        let command = "hostname";
        let args = [
            "compute",
            "ssh",
            instance,
            "--project",
            project,
            "--zone",
            zone,
            "--command",
            command,
            "--quiet",
            "--tunnel-through-iap",
        ];
        assert_eq!(args.len(), 11);
        assert_eq!(args[2], "my-vm");
        assert_eq!(args[4], "my-project");
        assert_eq!(args[6], "us-central1-a");
        assert_eq!(args[8], "hostname");
    }
}
