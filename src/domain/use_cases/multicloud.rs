//! Multi-cloud Inventory Command Builder
//!
//! Builds multi-cloud instance listing, sync, and comparison commands
//! for remote execution via SSH. Supports AWS, GCP, and Azure.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds multi-cloud inventory commands for remote execution.
pub struct MulticloudCommandBuilder;

impl MulticloudCommandBuilder {
    /// Validate a cloud provider name.
    ///
    /// # Errors
    ///
    /// Returns `CommandDenied` if the provider is not one of: aws, gcp, azure.
    pub fn validate_provider(provider: &str) -> Result<()> {
        match provider {
            "aws" | "gcp" | "azure" => Ok(()),
            _ => Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid cloud provider '{provider}': must be one of: aws, gcp, azure"
                ),
            }),
        }
    }

    /// Build a command to list instances from a single cloud provider.
    ///
    /// AWS: `aws ec2 describe-instances --output json`
    /// GCP: `gcloud compute instances list --format=json`
    /// Azure: `az vm list --output json`
    #[must_use]
    pub fn build_multicloud_list_command(provider: &str) -> String {
        match provider {
            "gcp" => "gcloud compute instances list --format=json 2>&1".to_string(),
            "azure" => "az vm list --output json 2>&1".to_string(),
            _ => format!(
                "{} && aws ec2 describe-instances --output json 2>&1",
                Self::banner(&format!("--- Provider: {provider} ---"))
            ),
        }
    }

    /// Build a command to sync inventory from all three cloud providers.
    ///
    /// Runs list commands for AWS, GCP, and Azure sequentially.
    #[must_use]
    pub fn build_multicloud_sync_command() -> String {
        "echo '=== AWS ===' && aws ec2 describe-instances --output json 2>&1; \
         echo '=== GCP ===' && gcloud compute instances list --format=json 2>&1; \
         echo '=== Azure ===' && az vm list --output json 2>&1"
            .to_string()
    }

    /// Build a command to compare instances between two cloud providers.
    ///
    /// Outputs instance lists from both providers for comparison.
    #[must_use]
    pub fn build_multicloud_compare_command(provider1: &str, provider2: &str) -> String {
        let cmd1 = Self::build_provider_list_snippet(provider1);
        let cmd2 = Self::build_provider_list_snippet(provider2);
        let banner1 = Self::banner(&format!("=== {provider1} ==="));
        let banner2 = Self::banner(&format!("=== {provider2} ==="));
        format!("{banner1} && {cmd1}; {banner2} && {cmd2}")
    }

    /// A `printf` that prints `text` and a newline, with `text` quoted once as
    /// a single word (`printf '%s\n' 'text'`), so a caller-supplied provider
    /// cannot leave the quotes nor be read as an option.
    fn banner(text: &str) -> String {
        format!("printf '%s\\n' {}", shell_escape(text))
    }

    /// Build the list snippet for a single provider (internal helper).
    #[must_use]
    fn build_provider_list_snippet(provider: &str) -> String {
        match provider {
            "gcp" => "gcloud compute instances list --format=json 2>&1".to_string(),
            "azure" => "az vm list --output json 2>&1".to_string(),
            _ => "aws ec2 describe-instances --output json 2>&1".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_provider ──

    #[test]
    fn test_validate_provider_valid() {
        assert!(MulticloudCommandBuilder::validate_provider("aws").is_ok());
        assert!(MulticloudCommandBuilder::validate_provider("gcp").is_ok());
        assert!(MulticloudCommandBuilder::validate_provider("azure").is_ok());
    }

    #[test]
    fn test_validate_provider_invalid() {
        assert!(MulticloudCommandBuilder::validate_provider("").is_err());
        assert!(MulticloudCommandBuilder::validate_provider("digitalocean").is_err());
        assert!(MulticloudCommandBuilder::validate_provider("AWS").is_err());
    }

    #[test]
    fn test_validate_provider_error_message() {
        let result = MulticloudCommandBuilder::validate_provider("openstack");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("openstack"));
                assert!(reason.contains("aws, gcp, azure"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── build_multicloud_list_command ──

    #[test]
    fn test_list_aws() {
        let cmd = MulticloudCommandBuilder::build_multicloud_list_command("aws");
        assert!(cmd.contains("aws ec2 describe-instances"));
        assert!(cmd.contains("--output json"));
    }

    #[test]
    fn test_list_gcp() {
        let cmd = MulticloudCommandBuilder::build_multicloud_list_command("gcp");
        assert!(cmd.contains("gcloud compute instances list"));
        assert!(cmd.contains("--format=json"));
    }

    #[test]
    fn test_list_azure() {
        let cmd = MulticloudCommandBuilder::build_multicloud_list_command("azure");
        assert!(cmd.contains("az vm list"));
        assert!(cmd.contains("--output json"));
    }

    // ── build_multicloud_sync_command ──

    #[test]
    fn test_sync_contains_all_providers() {
        let cmd = MulticloudCommandBuilder::build_multicloud_sync_command();
        assert!(cmd.contains("=== AWS ==="));
        assert!(cmd.contains("=== GCP ==="));
        assert!(cmd.contains("=== Azure ==="));
        assert!(cmd.contains("aws ec2"));
        assert!(cmd.contains("gcloud compute"));
        assert!(cmd.contains("az vm list"));
    }

    // ── build_multicloud_compare_command ──

    #[test]
    fn test_compare_aws_gcp() {
        let cmd = MulticloudCommandBuilder::build_multicloud_compare_command("aws", "gcp");
        assert!(cmd.contains("aws ec2 describe-instances"));
        assert!(cmd.contains("gcloud compute instances list"));
    }

    #[test]
    fn test_compare_azure_aws() {
        let cmd = MulticloudCommandBuilder::build_multicloud_compare_command("azure", "aws");
        assert!(cmd.contains("az vm list"));
        assert!(cmd.contains("aws ec2 describe-instances"));
    }

    #[test]
    fn test_compare_gcp_azure() {
        let cmd = MulticloudCommandBuilder::build_multicloud_compare_command("gcp", "azure");
        assert!(cmd.contains("gcloud compute"));
        assert!(cmd.contains("az vm list"));
    }

    #[test]
    fn test_compare_same_provider() {
        let cmd = MulticloudCommandBuilder::build_multicloud_compare_command("aws", "aws");
        // Should still work, producing two AWS sections
        assert!(cmd.contains("aws ec2 describe-instances"));
    }

    // ── build_provider_list_snippet ──

    #[test]
    fn test_provider_snippet_aws() {
        let cmd = MulticloudCommandBuilder::build_provider_list_snippet("aws");
        assert!(cmd.contains("aws ec2"));
    }

    #[test]
    fn test_provider_snippet_gcp() {
        let cmd = MulticloudCommandBuilder::build_provider_list_snippet("gcp");
        assert!(cmd.contains("gcloud"));
    }

    #[test]
    fn test_provider_snippet_azure() {
        let cmd = MulticloudCommandBuilder::build_provider_list_snippet("azure");
        assert!(cmd.contains("az vm"));
    }

    #[test]
    fn test_provider_snippet_unknown_defaults_to_aws() {
        let cmd = MulticloudCommandBuilder::build_provider_list_snippet("unknown");
        assert!(cmd.contains("aws ec2"));
    }

    #[test]
    fn test_banner_quotes_the_whole_text_once() {
        let cmd = MulticloudCommandBuilder::build_multicloud_list_command("a'; id; '");
        assert!(
            cmd.starts_with("printf '%s\\n' '--- Provider: a'\\''; id; '\\'' ---' && aws ec2"),
            "{cmd}"
        );
        let cmp = MulticloudCommandBuilder::build_multicloud_compare_command("aws", "gcp");
        assert!(
            cmp.starts_with("printf '%s\\n' '=== aws ===' && aws ec2"),
            "{cmp}"
        );
    }
}
