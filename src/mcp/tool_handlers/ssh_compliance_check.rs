//! SSH Compliance Check Tool Handler
//!
//! Runs CIS benchmark compliance checks including file permissions, SSH config,
//! firewall, password policy, and sysctl settings.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::sbom::SbomCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshComplianceCheckArgs {
    host: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
    /// When `true`, append an LLM-side summary of failing controls to
    /// the response. Requires the client to advertise the sampling
    /// capability; falls back to raw-only output otherwise.
    #[serde(default)]
    summarize: Option<bool>,
    /// Maximum tokens for the LLM summary (default: 512). Only
    /// meaningful with summarize=true.
    #[serde(default)]
    summary_max_tokens: Option<u32>,
}

impl_common_args!(SshComplianceCheckArgs);

#[mcp_standard_tool(
    name = "ssh_compliance_check",
    group = "security_scan",
    annotation = "read_only"
)]
pub struct ComplianceCheckTool;

impl StandardTool for ComplianceCheckTool {
    type Args = SshComplianceCheckArgs;

    const NAME: &'static str = "ssh_compliance_check";

    const DESCRIPTION: &'static str = "Run CIS benchmark compliance checks including file \
        permissions, SSH config, firewall, password policy, and sysctl settings.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "profile": {
                "type": "string",
                "description": "Compliance profile to check (default: cis-level1)",
                "enum": ["cis-level1", "cis-level2", "basic"]
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
            },
            "summarize": {
                "type": "boolean",
                "description": "When true, append an LLM-side summary of failing controls to the response. Requires the client to advertise the sampling capability; falls back to raw-only output otherwise."
            },
            "summary_max_tokens": {
                "type": "integer",
                "description": "Maximum tokens for the LLM summary (default: 512). Only meaningful with summarize=true.",
                "minimum": 32,
                "maximum": 4096
            }
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshComplianceCheckArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SbomCommandBuilder::build_compliance_command(
            args.profile.as_deref().unwrap_or("cis-level1"),
        ))
    }

    /// Optional LLM-side summary appended after the raw compliance
    /// output. Falls back to raw-only when the client does not
    /// advertise the sampling capability.
    async fn enrich(
        result: ToolCallResult,
        args: &Self::Args,
        output: &str,
        ctx: &ToolContext,
    ) -> Result<ToolCallResult> {
        if !args.summarize.unwrap_or(false) {
            return Ok(result);
        }
        let max_tokens = args.summary_max_tokens.unwrap_or(512);
        let prompt = "You are a compliance auditor. List the top 3 failing \
                      controls from this report in bullet points, one line \
                      each, no preamble. Mention the CIS/STIG benchmark id \
                      when present and a 1-line remediation summary.";
        let Some(summary) = ctx.sample(prompt, output, max_tokens).await? else {
            return Ok(result);
        };
        let mut text = String::new();
        for content in &result.content {
            if let ToolContent::Text { text: t } = content {
                text.push_str(t);
            }
        }
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("\n=== LLM SUMMARY ===\n");
        text.push_str(&summary);
        let mut enriched = ToolCallResult::text(text);
        enriched.structured_content = result.structured_content;
        enriched.is_error = result.is_error;
        Ok(enriched)
    }
}

pub type SshComplianceCheckHandler = StandardToolHandler<ComplianceCheckTool>;

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
        let handler = SshComplianceCheckHandler::new();
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
        let handler = SshComplianceCheckHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshComplianceCheckHandler::new();
        assert_eq!(handler.name(), "ssh_compliance_check");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        // Verify profile enum is in schema
        let profile = &schema_json["properties"]["profile"];
        assert!(profile["enum"].is_array());
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "profile": "cis-level2", "timeout_seconds": 120});
        let args: SshComplianceCheckArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.profile, Some("cis-level2".to_string()));
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshComplianceCheckArgs = serde_json::from_value(json).unwrap();
        assert!(args.profile.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshComplianceCheckArgs {
            host: "server1".to_string(),
            profile: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = ComplianceCheckTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("CIS COMPLIANCE"));
        assert!(cmd.contains("SSH Configuration"));
        assert!(cmd.contains("Firewall"));
        assert!(cmd.contains("Password Policy"));
    }

    #[test]
    fn test_build_command_basic_profile() {
        let args = SshComplianceCheckArgs {
            host: "server1".to_string(),
            profile: Some("basic".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = ComplianceCheckTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("BASIC COMPLIANCE"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshComplianceCheckArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.profile.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
        assert!(args.summarize.is_none());
        assert!(args.summary_max_tokens.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshComplianceCheckHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("profile"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
        assert!(props.contains_key("summarize"));
        assert!(props.contains_key("summary_max_tokens"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshComplianceCheckArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshComplianceCheckArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshComplianceCheckHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "server1",
            "profile": "cis-level1",
            "timeout_seconds": 90,
            "max_output": 4096,
            "save_output": "/tmp/out.txt",
            "summarize": true,
            "summary_max_tokens": 256
        });
        let args: SshComplianceCheckArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.profile, Some("cis-level1".to_string()));
        assert_eq!(args.timeout_seconds, Some(90));
        assert_eq!(args.max_output, Some(4096));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
        assert_eq!(args.summarize, Some(true));
        assert_eq!(args.summary_max_tokens, Some(256));
    }

    #[test]
    fn test_build_command_cis_level2() {
        let args = SshComplianceCheckArgs {
            host: "server1".to_string(),
            profile: Some("cis-level2".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = ComplianceCheckTool::build_command(&args, &test_host_config()).unwrap();
        // cis-level2 shares the full CIS check set with cis-level1.
        assert!(cmd.contains("CIS COMPLIANCE"));
        assert!(cmd.contains("Core Dumps"));
        assert!(cmd.contains("Sysctl Security"));
    }

    #[test]
    fn test_build_command_unknown_profile_falls_back_to_basic() {
        let args = SshComplianceCheckArgs {
            host: "server1".to_string(),
            profile: Some("does-not-exist".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = ComplianceCheckTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("BASIC COMPLIANCE"));
        assert!(!cmd.contains("CIS COMPLIANCE"));
    }

    #[test]
    fn test_build_command_default_profile_is_cis_level1() {
        // No profile -> build_command applies the "cis-level1" default.
        let args = SshComplianceCheckArgs {
            host: "server1".to_string(),
            profile: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = ComplianceCheckTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("CIS COMPLIANCE"));
        assert!(!cmd.contains("BASIC COMPLIANCE"));
    }
}
