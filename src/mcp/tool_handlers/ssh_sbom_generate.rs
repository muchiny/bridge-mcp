//! SSH SBOM Generate Tool Handler
//!
//! Generates a Software Bill of Materials listing all installed packages,
//! versions, and architecture on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::sbom::SbomCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshSbomGenerateArgs {
    host: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshSbomGenerateArgs);

#[mcp_standard_tool(
    name = "ssh_sbom_generate",
    group = "security_scan",
    annotation = "read_only"
)]
pub struct SbomGenerateTool;

impl StandardTool for SbomGenerateTool {
    type Args = SshSbomGenerateArgs;

    const NAME: &'static str = "ssh_sbom_generate";

    const DESCRIPTION: &'static str = "Generate a Software Bill of Materials (SBOM) listing all \
        installed packages, versions, and architecture on a remote host. Supports dpkg (Debian/Ubuntu), \
        rpm (RHEL/CentOS), and apk (Alpine); output is a TSV table (PACKAGE / VERSION / ARCH / STATUS). \
        Use this to inventory what is installed. To check for pending security updates use \
        ssh_vuln_scan instead. To audit CIS/STIG compliance posture use ssh_compliance_check instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: 60)",
                "minimum": 1,
                "maximum": 300
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from config)",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to local file"
            }
        },
        "required": ["host"]
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(_args: &SshSbomGenerateArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SbomCommandBuilder::build_sbom_command())
    }

    fn post_process(
        result: ToolCallResult,
        _args: &SshSbomGenerateArgs,
        output: &str,
        _dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        // Extract the TSV package list between === INSTALLED PACKAGES === and next ===
        // dpkg-query already outputs tab-separated: Package\tVersion\tArch\tStatus
        let mut in_packages = false;
        let mut tsv = String::from("PACKAGE\tVERSION\tARCH\tSTATUS\n");
        let mut other_sections = String::new();
        for line in output.lines() {
            if line.contains("=== INSTALLED PACKAGES ===") {
                in_packages = true;
                continue;
            }
            if line.starts_with("=== ") {
                in_packages = false;
                other_sections.push_str(line);
                other_sections.push('\n');
                continue;
            }
            if in_packages && !line.trim().is_empty() {
                tsv.push_str(line);
                tsv.push('\n');
            } else if !in_packages && !line.trim().is_empty() {
                other_sections.push_str(line);
                other_sections.push('\n');
            }
        }
        if tsv.lines().count() <= 1 {
            // No package data extracted — return original
            return result;
        }
        // Append non-package sections after TSV
        if !other_sections.is_empty() {
            tsv.push_str("\n--- System Info ---\n");
            tsv.push_str(&other_sections);
        }
        ToolCallResult::text(tsv)
    }
}

pub type SshSbomGenerateHandler = StandardToolHandler<SbomGenerateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::default(),
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),

            #[cfg(feature = "winrm")]
            winrm_use_tls: None,

            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,

            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,

            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        }
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSbomGenerateHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshSbomGenerateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshSbomGenerateHandler::new();
        assert_eq!(handler.name(), "ssh_sbom_generate");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "timeout_seconds": 120});
        let args: SshSbomGenerateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshSbomGenerateArgs = serde_json::from_value(json).unwrap();
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshSbomGenerateArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SbomGenerateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("INSTALLED PACKAGES"));
        assert!(cmd.contains("dpkg-query"));
        assert!(cmd.contains("rpm -qa"));
    }

    #[test]
    fn test_post_process_extracts_packages_section() {
        // Drives the in_packages=true branch of post_process — a TSV with
        // package data is produced and other sections are appended.
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let args = SshSbomGenerateArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let raw = "=== SYSTEM ===\n\
                   Linux foo 5.15.0\n\
                   === INSTALLED PACKAGES ===\n\
                   bash\t5.1\tamd64\tinstalled\n\
                   curl\t7.81\tamd64\tinstalled\n\
                   === END ===\n\
                   done\n";
        let base = ToolCallResult::text(raw.to_string());
        let processed = SbomGenerateTool::post_process(base, &args, raw, &dr);
        // Result should contain the TSV header and at least one package row.
        if let crate::ports::protocol::ToolContent::Text { text } = &processed.content[0] {
            assert!(text.contains("PACKAGE\tVERSION\tARCH\tSTATUS"));
            assert!(text.contains("bash\t5.1\tamd64\tinstalled"));
            assert!(text.contains("curl"));
            // Other sections appended after the TSV.
            assert!(text.contains("System Info") || text.contains("=== SYSTEM ==="));
        } else {
            panic!("Expected Text content");
        }
    }

    #[test]
    fn test_post_process_no_packages_returns_input() {
        // No `=== INSTALLED PACKAGES ===` marker — branch returns input
        // unchanged because tsv has only the header line.
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let args = SshSbomGenerateArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let raw = "no packages marker here\nsome content\n";
        let base = ToolCallResult::text(raw.to_string());
        let processed = SbomGenerateTool::post_process(base, &args, raw, &dr);
        if let crate::ports::protocol::ToolContent::Text { text } = &processed.content[0] {
            // Original input preserved (no TSV header inserted).
            assert!(!text.contains("PACKAGE\tVERSION\tARCH\tSTATUS"));
        } else {
            panic!("Expected Text content");
        }
    }

    #[test]
    fn test_post_process_packages_only_no_other_sections() {
        // Package marker present but no following === sections.
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let args = SshSbomGenerateArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let raw = "=== INSTALLED PACKAGES ===\nbash\t5.1\tamd64\tinstalled\n";
        let base = ToolCallResult::text(raw.to_string());
        let processed = SbomGenerateTool::post_process(base, &args, raw, &dr);
        if let crate::ports::protocol::ToolContent::Text { text } = &processed.content[0] {
            assert!(text.contains("PACKAGE\tVERSION\tARCH\tSTATUS"));
            assert!(text.contains("bash"));
        } else {
            panic!("Expected Text content");
        }
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshSbomGenerateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshSbomGenerateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshSbomGenerateHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 99})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
