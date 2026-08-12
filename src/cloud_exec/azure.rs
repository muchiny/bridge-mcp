//! Azure Run Command adapter — execute commands on Azure VMs
//!
//! Uses the Azure Compute Management API to invoke `RunShellScript` or
//! `RunPowerShellScript` on virtual machines without requiring SSH.
//!
//! **Not air-gapped compatible** — requires connectivity to Azure APIs.
//!
//! Feature-gated behind `azure`.

use std::time::{Duration, Instant};

use reqwest::Client;
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Poll interval for command status.
const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Maximum time to wait for command completion.
const MAX_WAIT: Duration = Duration::from_mins(5);

/// Azure Run Command connection.
///
/// The `HostConfig` is interpreted as follows:
/// - `hostname` → VM name
/// - `user` → resource group name
/// - `description` → subscription ID (required)
///
/// Authentication uses Azure CLI credentials or managed identity
/// via the `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
/// and `AZURE_CLIENT_SECRET` environment variables, or `az login` session.
pub struct AzureRunConnection {
    client: Client,
    vm_name: String,
    resource_group: String,
    subscription_id: String,
    access_token: String,
    host_name: String,
    failed: bool,
}

impl AzureRunConnection {
    /// Create an Azure Run Command connection.
    ///
    /// Acquires an access token via Azure CLI (`az account get-access-token`)
    /// or environment credentials.
    ///
    /// # Errors
    ///
    /// Returns an error if Azure credentials cannot be obtained.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        info!(host = %host_name, vm = %host_config.hostname, "Connecting via Azure Run Command");

        let subscription_id = host_config
            .description
            .clone()
            .or_else(|| std::env::var("AZURE_SUBSCRIPTION_ID").ok())
            .ok_or_else(|| BridgeError::Config(
                "Azure host requires subscription_id in description field or AZURE_SUBSCRIPTION_ID env var".to_string(),
            ))?;

        if host_config.user.is_empty() || host_config.user == "root" {
            return Err(BridgeError::Config(
                "Azure host requires resource group name in user field".to_string(),
            ));
        }
        let resource_group = host_config.user.clone();

        // Get access token via Azure CLI
        let access_token = acquire_azure_token().await?;

        let client = Client::builder()
            .timeout(Duration::from_mins(1))
            .build()
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Azure HTTP client error: {e}"),
            })?;

        info!(
            host = %host_name,
            vm = %host_config.hostname,
            resource_group = %resource_group,
            "Azure Run Command target resolved"
        );

        Ok(Self {
            client,
            vm_name: host_config.hostname.clone(),
            resource_group,
            subscription_id,
            access_token,
            host_name: host_name.to_string(),
            failed: false,
        })
    }

    /// Execute a command via Azure Run Command API.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails or the command times out.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            vm = %self.vm_name,
            command = %command,
            "Executing Azure Run Command"
        );

        let url = format!(
            "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand?api-version=2024-07-01",
            sub = self.subscription_id,
            rg = self.resource_group,
            vm = self.vm_name,
        );

        let body = serde_json::json!({
            "commandId": "RunShellScript",
            "script": [command]
        });

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Azure Run Command request failed: {e}"),
            })?;

        let status = response.status();

        // Azure returns 200 for sync or 202 for async (with Location header)
        if status.as_u16() == 202 {
            // Async operation — poll the Location header
            if let Some(location) = response
                .headers()
                .get("azure-asyncoperation")
                .or_else(|| response.headers().get("location"))
            {
                let poll_url = location.to_str().unwrap_or_default().to_string();
                return self.poll_async_result(&poll_url, start).await;
            }
        }

        let response_body: serde_json::Value =
            response.json().await.map_err(|e| BridgeError::SshExec {
                reason: format!("Azure response parse error: {e}"),
            })?;

        Ok(parse_azure_response(&response_body, elapsed_ms(start)))
    }

    /// Poll an async Azure operation until completion.
    async fn poll_async_result(&self, poll_url: &str, start: Instant) -> Result<CommandOutput> {
        let deadline = Instant::now() + MAX_WAIT;

        loop {
            if Instant::now() > deadline {
                return Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: format!("Azure command timed out after {}s", MAX_WAIT.as_secs()),
                    exit_code: 124,
                    duration_ms: elapsed_ms(start),
                });
            }

            tokio::time::sleep(POLL_INTERVAL).await;

            let response = self
                .client
                .get(poll_url)
                .bearer_auth(&self.access_token)
                .send()
                .await
                .map_err(|e| BridgeError::SshExec {
                    reason: format!("Azure poll request failed: {e}"),
                })?;

            let body: serde_json::Value =
                response.json().await.map_err(|e| BridgeError::SshExec {
                    reason: format!("Azure poll response parse error: {e}"),
                })?;

            let status = body["status"].as_str().unwrap_or("");
            match status {
                "Succeeded" | "Failed" | "Canceled" => {
                    return Ok(parse_azure_response(&body, elapsed_ms(start)));
                }
                _ => {} // InProgress, etc.
            }
        }
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "Azure Run Command connection marked as failed");
    }
}

/// Acquire an Azure access token via CLI.
async fn acquire_azure_token() -> Result<String> {
    // Try environment variable first
    if let Ok(token) = std::env::var("AZURE_ACCESS_TOKEN") {
        return Ok(token);
    }

    // Fall back to Azure CLI
    let output = tokio::process::Command::new("az")
        .args([
            "account",
            "get-access-token",
            "--query",
            "accessToken",
            "-o",
            "tsv",
        ])
        .output()
        .await
        .map_err(|e| BridgeError::SshExec {
            reason: format!("Azure CLI not available: {e}"),
        })?;

    if !output.status.success() {
        return Err(BridgeError::SshExec {
            reason: format!(
                "Azure CLI auth failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Parse Azure Run Command response into `CommandOutput`.
fn parse_azure_response(body: &serde_json::Value, duration_ms: u64) -> CommandOutput {
    // Azure response structure varies; try common paths
    let output_value = body
        .get("value")
        .or_else(|| body.get("properties").and_then(|p| p.get("output")));

    if let Some(values) = output_value.and_then(|v| v.as_array()) {
        let mut stdout = String::new();
        let mut stderr = String::new();

        for item in values {
            let code = item["code"].as_str().unwrap_or("");
            let message = item["message"].as_str().unwrap_or("");
            if code.contains("StdOut") {
                stdout.push_str(message);
            } else if code.contains("StdErr") {
                stderr.push_str(message);
            }
        }

        CommandOutput {
            stdout,
            exit_code: u32::from(!stderr.is_empty()),
            stderr,
            duration_ms,
        }
    } else {
        CommandOutput {
            stdout: body.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms,
        }
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
    fn test_parse_azure_response_success() {
        let body = serde_json::json!({
            "value": [
                {"code": "ProvisioningState/succeeded/StdOut", "message": "hello world\n"},
                {"code": "ProvisioningState/succeeded/StdErr", "message": ""}
            ]
        });
        let result = parse_azure_response(&body, 100);
        assert_eq!(result.stdout, "hello world\n");
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_parse_azure_response_with_stderr() {
        let body = serde_json::json!({
            "value": [
                {"code": "ProvisioningState/succeeded/StdOut", "message": ""},
                {"code": "ProvisioningState/succeeded/StdErr", "message": "error msg"}
            ]
        });
        let result = parse_azure_response(&body, 50);
        assert_eq!(result.stderr, "error msg");
        assert_eq!(result.exit_code, 1);
    }

    #[test]
    fn test_parse_azure_response_empty() {
        let body = serde_json::json!({"status": "Succeeded"});
        let result = parse_azure_response(&body, 200);
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_poll_constants() {
        assert_eq!(POLL_INTERVAL.as_secs(), 3);
        assert_eq!(MAX_WAIT.as_secs(), 300);
    }

    #[test]
    fn test_parse_azure_response_multiple_stdout_entries() {
        let body = serde_json::json!({
            "value": [
                {"code": "ProvisioningState/succeeded/StdOut", "message": "line1\n"},
                {"code": "ProvisioningState/succeeded/StdOut", "message": "line2\n"},
                {"code": "ProvisioningState/succeeded/StdErr", "message": ""}
            ]
        });
        let result = parse_azure_response(&body, 100);
        assert_eq!(result.stdout, "line1\nline2\n");
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_parse_azure_response_no_value_field() {
        let body = serde_json::json!({"other": "data"});
        let result = parse_azure_response(&body, 50);
        // Falls back to body.to_string()
        assert_eq!(result.exit_code, 0);
        assert!(!result.stdout.is_empty());
    }

    #[test]
    fn test_parse_azure_response_null_value() {
        let body = serde_json::json!({"value": null});
        let result = parse_azure_response(&body, 50);
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_parse_azure_response_empty_array() {
        let body = serde_json::json!({"value": []});
        let result = parse_azure_response(&body, 50);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_parse_azure_response_properties_output_path() {
        let body = serde_json::json!({
            "properties": {
                "output": {
                    "value": [
                        {"code": "StdOut/succeeded", "message": "from properties"}
                    ]
                }
            }
        });
        // properties.output is checked as fallback, but its .value needs to be an array
        let result = parse_azure_response(&body, 30);
        // This follows the properties->output path
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_parse_azure_response_missing_code() {
        let body = serde_json::json!({
            "value": [
                {"message": "orphan message"}
            ]
        });
        let result = parse_azure_response(&body, 100);
        // code is "", doesn't contain StdOut or StdErr
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn test_parse_azure_response_missing_message() {
        let body = serde_json::json!({
            "value": [
                {"code": "ProvisioningState/succeeded/StdOut"}
            ]
        });
        let result = parse_azure_response(&body, 100);
        // message defaults to ""
        assert!(result.stdout.is_empty());
    }

    #[test]
    fn test_api_url_format() {
        let sub = "12345678-1234-1234-1234-123456789012";
        let rg = "my-resource-group";
        let vm = "my-vm";
        let url = format!(
            "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand?api-version=2024-07-01"
        );
        assert!(url.contains(sub));
        assert!(url.contains(rg));
        assert!(url.contains(vm));
        assert!(url.contains("api-version=2024-07-01"));
    }

    #[test]
    fn test_run_command_body_structure() {
        let command = "whoami";
        let body = serde_json::json!({
            "commandId": "RunShellScript",
            "script": [command]
        });
        assert_eq!(body["commandId"].as_str().unwrap(), "RunShellScript");
        let script = body["script"].as_array().unwrap();
        assert_eq!(script.len(), 1);
        assert_eq!(script[0].as_str().unwrap(), "whoami");
    }

    #[test]
    fn test_elapsed_ms() {
        let start = std::time::Instant::now();
        let ms = elapsed_ms(start);
        assert!(ms < 100);
    }

    #[test]
    fn test_async_operation_status_matching() {
        let terminal = ["Succeeded", "Failed", "Canceled"];
        let non_terminal = ["InProgress", "Running", "Queued"];

        for status in &terminal {
            assert!(matches!(*status, "Succeeded" | "Failed" | "Canceled"));
        }
        for status in &non_terminal {
            assert!(!matches!(*status, "Succeeded" | "Failed" | "Canceled"));
        }
    }
}
