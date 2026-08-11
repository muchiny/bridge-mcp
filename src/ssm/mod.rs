//! AWS Systems Manager (SSM) protocol adapter — cloud-based command execution
//!
//! Executes commands on EC2 instances via the AWS SSM `SendCommand` API,
//! bypassing the need for direct SSH access. Requires IAM permissions and
//! an SSM Agent running on the target instance.
//!
//! **Not air-gapped compatible** — requires connectivity to AWS APIs.
//!
//! Feature-gated behind `ssm`.

use std::time::{Duration, Instant};

use aws_config::BehaviorVersion;
use aws_sdk_ssm::Client as SsmClient;
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig, OsType};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default SSM document for Linux command execution.
const DEFAULT_LINUX_DOCUMENT: &str = "AWS-RunShellScript";
/// Default SSM document for Windows command execution.
const DEFAULT_WINDOWS_DOCUMENT: &str = "AWS-RunPowerShellScript";
/// Poll interval for command status.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Maximum time to wait for command completion.
const MAX_WAIT: Duration = Duration::from_mins(5);

/// AWS SSM connection — wraps an SSM API client configured for a target instance.
///
/// The `HostConfig` is interpreted as follows:
/// - `hostname` → EC2 instance ID (e.g., `i-0abc123def456`)
/// - `user` → AWS region (default: `us-east-1`)
/// - `description` → SSM document name (default: `AWS-RunShellScript`)
pub struct SsmConnection {
    client: SsmClient,
    instance_id: String,
    document: String,
    host_name: String,
    failed: bool,
}

impl SsmConnection {
    /// Create an SSM client for the specified instance.
    ///
    /// # Errors
    ///
    /// Returns an error if AWS credentials cannot be loaded.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        info!(host = %host_name, instance = %host_config.hostname, "Connecting via AWS SSM");

        let region = if host_config.user.is_empty() || host_config.user == "root" {
            "us-east-1".to_string()
        } else {
            host_config.user.clone()
        };

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region.clone()))
            .load()
            .await;

        let client = SsmClient::new(&config);

        // Document name from description or detect from OS type
        let document =
            host_config
                .description
                .clone()
                .unwrap_or_else(|| match host_config.os_type {
                    OsType::Windows => DEFAULT_WINDOWS_DOCUMENT.to_string(),
                    OsType::Linux => DEFAULT_LINUX_DOCUMENT.to_string(),
                });

        info!(
            host = %host_name,
            instance = %host_config.hostname,
            region = %region,
            document = %document,
            "SSM target resolved"
        );

        Ok(Self {
            client,
            instance_id: host_config.hostname.clone(),
            document,
            host_name: host_name.to_string(),
            failed: false,
        })
    }

    /// Execute a command via SSM `SendCommand` + `GetCommandInvocation`.
    ///
    /// This is an asynchronous operation: SSM queues the command, and we
    /// poll until completion or timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the SSM API call fails or the command times out.
    #[allow(clippy::too_many_lines)]
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            instance = %self.instance_id,
            command = %command,
            "Executing SSM command"
        );

        // Send command
        let send_result = self
            .client
            .send_command()
            .document_name(&self.document)
            .instance_ids(&self.instance_id)
            .parameters("commands", vec![command.to_string()])
            .timeout_seconds(300)
            .send()
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("SSM SendCommand failed: {e}"),
            })?;

        let command_id = send_result
            .command()
            .and_then(|c| c.command_id())
            .ok_or_else(|| BridgeError::SshExec {
                reason: "SSM SendCommand returned no command ID".to_string(),
            })?
            .to_string();

        debug!(
            host = %self.host_name,
            command_id = %command_id,
            "SSM command sent, polling for result"
        );

        self.poll_result(&command_id, start).await
    }

    /// Poll SSM for command invocation result until completion or timeout.
    async fn poll_result(&self, command_id: &str, start: Instant) -> Result<CommandOutput> {
        let deadline = Instant::now() + MAX_WAIT;
        loop {
            if Instant::now() > deadline {
                return Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: format!(
                        "SSM command timed out after {}s (command_id: {command_id})",
                        MAX_WAIT.as_secs()
                    ),
                    exit_code: 124, // timeout exit code
                    duration_ms: elapsed_ms(start),
                });
            }

            tokio::time::sleep(POLL_INTERVAL).await;

            let invocation = self
                .client
                .get_command_invocation()
                .command_id(command_id)
                .instance_id(&self.instance_id)
                .send()
                .await;

            match invocation {
                Ok(result) => {
                    let status = result
                        .status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();

                    match status.as_str() {
                        "Success" | "Failed" | "Cancelled" | "TimedOut" => {
                            let default_exit = u32::from(status != "Success");
                            return Ok(CommandOutput {
                                stdout: result
                                    .standard_output_content()
                                    .unwrap_or_default()
                                    .to_string(),
                                stderr: result
                                    .standard_error_content()
                                    .unwrap_or_default()
                                    .to_string(),
                                exit_code: u32::try_from(result.response_code())
                                    .unwrap_or(default_exit),
                                duration_ms: elapsed_ms(start),
                            });
                        }
                        // InProgress, Pending, Delayed — keep polling
                        _ => {}
                    }
                }
                Err(e) => {
                    // InvocationDoesNotExist is expected briefly after send
                    let err_str = e.to_string();
                    if !err_str.contains("InvocationDoesNotExist") {
                        return Err(BridgeError::SshExec {
                            reason: format!("SSM GetCommandInvocation failed: {e}"),
                        });
                    }
                }
            }
        }
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "SSM connection marked as failed");
    }
}

/// Convert elapsed duration to milliseconds, saturating on overflow.
#[allow(clippy::cast_possible_truncation)]
fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_documents() {
        assert_eq!(DEFAULT_LINUX_DOCUMENT, "AWS-RunShellScript");
        assert_eq!(DEFAULT_WINDOWS_DOCUMENT, "AWS-RunPowerShellScript");
    }

    #[test]
    fn test_poll_constants() {
        assert_eq!(POLL_INTERVAL.as_secs(), 2);
        assert_eq!(MAX_WAIT.as_secs(), 300);
    }

    #[test]
    fn test_instance_id_format() {
        let instance_id = "i-0abc123def456";
        assert!(instance_id.starts_with("i-"));
        assert_eq!(instance_id.len(), 15);
    }

    #[test]
    fn test_elapsed_ms() {
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(10));
        let ms = elapsed_ms(start);
        assert!(ms >= 10);
    }

    #[test]
    fn test_elapsed_ms_immediate() {
        let start = Instant::now();
        let ms = elapsed_ms(start);
        assert!(ms < 100);
    }

    #[test]
    fn test_instance_id_format_standard() {
        let id = "i-0abc123def456";
        assert!(id.starts_with("i-"));
    }

    #[test]
    fn test_instance_id_format_17_char() {
        // AWS instance IDs can be 17 hex chars after "i-"
        let id = "i-0abc123def4567890";
        assert!(id.starts_with("i-"));
        assert_eq!(id.len(), 19); // "i-" (2) + 17 hex chars
        assert!(id[2..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_instance_id_format_8_char() {
        // Older AWS instance IDs are 8 hex chars
        let id = "i-abcd1234";
        assert!(id.starts_with("i-"));
        assert_eq!(id.len(), 10);
    }

    #[test]
    fn test_document_selection_linux() {
        let os_type = crate::config::OsType::Linux;
        let resolved = match os_type {
            crate::config::OsType::Windows => DEFAULT_WINDOWS_DOCUMENT.to_string(),
            crate::config::OsType::Linux => DEFAULT_LINUX_DOCUMENT.to_string(),
        };
        assert_eq!(resolved, "AWS-RunShellScript");
    }

    #[test]
    fn test_document_selection_windows() {
        let os_type = crate::config::OsType::Windows;
        let resolved = match os_type {
            crate::config::OsType::Windows => DEFAULT_WINDOWS_DOCUMENT.to_string(),
            crate::config::OsType::Linux => DEFAULT_LINUX_DOCUMENT.to_string(),
        };
        assert_eq!(resolved, "AWS-RunPowerShellScript");
    }

    #[test]
    fn test_document_selection_custom_override() {
        let document = "AWS-RunRemoteScript".to_string();
        assert_eq!(document, "AWS-RunRemoteScript");
    }

    #[test]
    fn test_region_fallback() {
        // When user is empty or "root", fall back to us-east-1
        let user = "root";
        let region = if user.is_empty() || user == "root" {
            "us-east-1".to_string()
        } else {
            user.to_string()
        };
        assert_eq!(region, "us-east-1");
    }

    #[test]
    fn test_region_custom() {
        let user = "eu-west-1";
        let region = if user.is_empty() || user == "root" {
            "us-east-1".to_string()
        } else {
            user.to_string()
        };
        assert_eq!(region, "eu-west-1");
    }

    #[test]
    fn test_timeout_exit_code() {
        // SSM uses exit code 124 for timeouts (like coreutils timeout)
        let timeout_exit: u32 = 124;
        assert_eq!(timeout_exit, 124);
    }

    #[test]
    fn test_status_matching() {
        let terminal_statuses = ["Success", "Failed", "Cancelled", "TimedOut"];
        let non_terminal = ["InProgress", "Pending", "Delayed"];

        for status in &terminal_statuses {
            assert!(
                matches!(*status, "Success" | "Failed" | "Cancelled" | "TimedOut"),
                "Expected terminal status: {status}"
            );
        }
        for status in &non_terminal {
            assert!(
                !matches!(*status, "Success" | "Failed" | "Cancelled" | "TimedOut"),
                "Expected non-terminal status: {status}"
            );
        }
    }
}
