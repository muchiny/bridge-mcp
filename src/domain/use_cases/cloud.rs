//! Cloud Provider Command Builder
//!
//! Builds cloud CLI commands (AWS, GCP, Azure) for remote execution via SSH.
//! Supports AWS CLI invocation, cloud metadata detection, tag retrieval,
//! and cost analysis.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds cloud provider commands for remote execution.
pub struct CloudCommandBuilder;

impl CloudCommandBuilder {
    /// Validate an AWS service name (alphanumeric, hyphens only).
    ///
    /// # Errors
    ///
    /// Returns `CommandDenied` if the service name contains invalid characters
    /// or starts with `-`.
    pub fn validate_aws_service(service: &str) -> Result<()> {
        super::shell::refuse_option_like("service", service)?;
        if service.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "AWS service name cannot be empty".to_string(),
            });
        }
        if !service
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid AWS service name '{service}': only alphanumeric and hyphens allowed"
                ),
            });
        }
        Ok(())
    }

    /// Validate a subcommand (no shell metacharacters).
    ///
    /// # Errors
    ///
    /// Returns `CommandDenied` if the subcommand contains shell injection characters
    /// or starts with `-`.
    pub fn validate_subcommand(cmd: &str) -> Result<()> {
        super::shell::refuse_option_like("subcommand", cmd)?;
        if cmd.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Subcommand cannot be empty".to_string(),
            });
        }
        let forbidden = ['|', ';', '&', '`', '$', '(', ')', '{', '}', '<', '>'];
        for ch in &forbidden {
            if cmd.contains(*ch) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Subcommand contains forbidden character '{ch}': possible shell injection"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Build an AWS CLI command.
    ///
    /// Constructs: `aws SERVICE SUBCOMMAND [ARGS] --output json 2>&1`
    #[must_use]
    pub fn build_aws_cli_command(service: &str, subcommand: &str, args: Option<&str>) -> String {
        let mut cmd = format!("aws {} {}", shell_escape(service), shell_escape(subcommand));
        if let Some(extra) = args {
            cmd.push(' ');
            cmd.push_str(&shell_escape(extra));
        }
        cmd.push_str(" --output json 2>&1");
        cmd
    }

    /// Build a cloud metadata detection command.
    ///
    /// Auto-detects the cloud provider by querying metadata endpoints.
    #[must_use]
    pub fn build_cloud_metadata_command() -> String {
        "curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null && echo AWS \
         || curl -s -m 2 -H 'Metadata-Flavor: Google' \
         http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null && echo GCP \
         || curl -s -m 2 -H 'Metadata: true' \
         'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null \
         && echo Azure || echo 'No cloud metadata available'"
            .to_string()
    }

    /// Build a cloud tags retrieval command.
    ///
    /// Queries instance tags from the cloud provider metadata endpoint.
    #[must_use]
    pub fn build_cloud_tags_command(provider: Option<&str>) -> String {
        match provider.unwrap_or("aws") {
            "gcp" => "curl -s -H 'Metadata-Flavor: Google' \
                      'http://metadata.google.internal/computeMetadata/v1/instance/tags' \
                      2>/dev/null"
                .to_string(),
            "azure" => "curl -s -H 'Metadata: true' \
                        'http://169.254.169.254/metadata/instance/compute/tagsList\
                        ?api-version=2021-02-01' 2>/dev/null"
                .to_string(),
            _ => "curl -s http://169.254.169.254/latest/meta-data/tags/instance/ 2>/dev/null"
                .to_string(),
        }
    }

    /// Build a cloud cost retrieval command (AWS Cost Explorer).
    ///
    /// Constructs: `aws ce get-cost-and-usage ...`
    #[must_use]
    pub fn build_cloud_cost_command(service: Option<&str>, period: Option<&str>) -> String {
        let time_period = period.unwrap_or("7d");
        let days = time_period
            .strip_suffix('d')
            .and_then(|d| d.parse::<u32>().ok())
            .unwrap_or(7);
        let mut cmd = format!(
            "aws ce get-cost-and-usage \
             --time-period Start=$(date -d '{days} days ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
             --granularity DAILY --metrics BlendedCost"
        );
        if let Some(svc) = service {
            // Build the JSON first (it escapes `svc` for JSON), then quote the
            // whole document once for the shell.
            let filter = serde_json::json!({
                "Dimensions": {"Key": "SERVICE", "Values": [svc]}
            })
            .to_string();
            let _ = write!(cmd, " --filter {}", shell_escape(&filter));
        }
        cmd.push_str(" --output json 2>&1");
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_aws_service ──

    #[test]
    fn test_validate_aws_service_valid() {
        assert!(CloudCommandBuilder::validate_aws_service("s3").is_ok());
        assert!(CloudCommandBuilder::validate_aws_service("ec2").is_ok());
        assert!(CloudCommandBuilder::validate_aws_service("iam").is_ok());
        assert!(CloudCommandBuilder::validate_aws_service("cost-explorer").is_ok());
    }

    #[test]
    fn test_validate_aws_service_empty() {
        assert!(CloudCommandBuilder::validate_aws_service("").is_err());
    }

    #[test]
    fn test_validate_aws_service_shell_injection() {
        assert!(CloudCommandBuilder::validate_aws_service("s3;rm").is_err());
        assert!(CloudCommandBuilder::validate_aws_service("ec2 && echo").is_err());
        assert!(CloudCommandBuilder::validate_aws_service("s3|cat").is_err());
    }

    // ── validate_subcommand ──

    #[test]
    fn test_validate_subcommand_valid() {
        assert!(CloudCommandBuilder::validate_subcommand("describe-instances").is_ok());
        assert!(CloudCommandBuilder::validate_subcommand("list-buckets").is_ok());
        assert!(CloudCommandBuilder::validate_subcommand("get-object").is_ok());
    }

    #[test]
    fn test_validate_subcommand_empty() {
        assert!(CloudCommandBuilder::validate_subcommand("").is_err());
    }

    #[test]
    fn test_validate_subcommand_injection() {
        assert!(CloudCommandBuilder::validate_subcommand("list; rm -rf /").is_err());
        assert!(CloudCommandBuilder::validate_subcommand("list | cat").is_err());
        assert!(CloudCommandBuilder::validate_subcommand("$(whoami)").is_err());
        assert!(CloudCommandBuilder::validate_subcommand("list`id`").is_err());
    }

    // ── build_aws_cli_command ──

    #[test]
    fn test_build_aws_cli_basic() {
        let cmd = CloudCommandBuilder::build_aws_cli_command("s3", "ls", None);
        assert!(cmd.contains("aws 's3' 'ls'"));
        assert!(cmd.contains("--output json"));
        assert!(cmd.ends_with("2>&1"));
    }

    #[test]
    fn test_build_aws_cli_with_args() {
        let cmd = CloudCommandBuilder::build_aws_cli_command(
            "ec2",
            "describe-instances",
            Some("--region us-east-1"),
        );
        assert!(cmd.contains("aws 'ec2' 'describe-instances'"));
        assert!(cmd.contains("'--region us-east-1'"));
        assert!(cmd.contains("--output json"));
    }

    // ── build_cloud_metadata_command ──

    #[test]
    fn test_build_cloud_metadata_command() {
        let cmd = CloudCommandBuilder::build_cloud_metadata_command();
        assert!(cmd.contains("169.254.169.254"));
        assert!(cmd.contains("AWS"));
        assert!(cmd.contains("GCP"));
        assert!(cmd.contains("Azure"));
        assert!(cmd.contains("No cloud metadata available"));
    }

    // ── build_cloud_tags_command ──

    #[test]
    fn test_build_cloud_tags_default_aws() {
        let cmd = CloudCommandBuilder::build_cloud_tags_command(None);
        assert!(cmd.contains("169.254.169.254/latest/meta-data/tags"));
    }

    #[test]
    fn test_build_cloud_tags_gcp() {
        let cmd = CloudCommandBuilder::build_cloud_tags_command(Some("gcp"));
        assert!(cmd.contains("Metadata-Flavor: Google"));
        assert!(cmd.contains("tags"));
    }

    #[test]
    fn test_build_cloud_tags_azure() {
        let cmd = CloudCommandBuilder::build_cloud_tags_command(Some("azure"));
        assert!(cmd.contains("Metadata: true"));
        assert!(cmd.contains("tagsList"));
    }

    // ── build_cloud_cost_command ──

    #[test]
    fn test_build_cloud_cost_default() {
        let cmd = CloudCommandBuilder::build_cloud_cost_command(None, None);
        assert!(cmd.contains("aws ce get-cost-and-usage"));
        assert!(cmd.contains("7 days ago"));
        assert!(cmd.contains("--granularity DAILY"));
        assert!(cmd.contains("--metrics BlendedCost"));
    }

    #[test]
    fn test_build_cloud_cost_with_service() {
        let cmd = CloudCommandBuilder::build_cloud_cost_command(Some("Amazon S3"), None);
        assert!(cmd.contains("SERVICE"));
        assert!(cmd.contains("Amazon S3"));
    }

    #[test]
    fn test_build_cloud_cost_with_period() {
        let cmd = CloudCommandBuilder::build_cloud_cost_command(None, Some("30d"));
        assert!(cmd.contains("30 days ago"));
    }

    #[test]
    fn test_cloud_cost_service_is_one_quoted_json_word() {
        for svc in ["x; id #", "$(id)", "x';id;'"] {
            let cmd = CloudCommandBuilder::build_cloud_cost_command(Some(svc), None);
            let filter = cmd
                .split(" --filter ")
                .nth(1)
                .and_then(|r| r.split(" --output").next())
                .unwrap();
            assert!(filter.starts_with("'{\"Dimensions\""), "{filter}");
            let json = filter.trim_matches('\'').replace("'\\''", "'");
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(v["Dimensions"]["Values"][0], svc);
        }
    }

    #[test]
    fn test_validate_aws_service_and_subcommand_refuse_a_leading_dash() {
        let err = CloudCommandBuilder::validate_aws_service("-x").unwrap_err();
        assert!(err.to_string().contains("'service'"), "{err}");
        let err = CloudCommandBuilder::validate_subcommand("--debug").unwrap_err();
        assert!(err.to_string().contains("'subcommand'"), "{err}");
    }
}
