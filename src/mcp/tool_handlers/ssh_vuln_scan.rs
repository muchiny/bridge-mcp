//! SSH Vulnerability Scan Tool Handler
//!
//! Scans for known vulnerabilities using the system's native package manager
//! security checks.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::sbom::SbomCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshVulnScanArgs {
    host: String,
    /// When `true`, append an LLM-side summary of the output to the
    /// response. Requires the client to advertise the sampling
    /// capability; falls back to raw-only output otherwise.
    #[serde(default)]
    summarize: Option<bool>,
    /// Maximum tokens for the LLM summary (default: 512). Only
    /// meaningful with summarize=true.
    #[serde(default)]
    summary_max_tokens: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshVulnScanArgs);

#[mcp_standard_tool(
    name = "ssh_vuln_scan",
    group = "security_scan",
    annotation = "read_only"
)]
pub struct VulnScanTool;

impl StandardTool for VulnScanTool {
    type Args = SshVulnScanArgs;

    const NAME: &'static str = "ssh_vuln_scan";

    const DESCRIPTION: &'static str = "Scan for pending security updates and kernel version on a \
        remote host using the native package manager (apt, yum/dnf, apk). Reports upgradable \
        packages with security tags, kernel version, total pending update count, and last update \
        timestamp. Set summarize=true to append an LLM-generated bullet list of the top CVEs \
        (requires the client to advertise the sampling capability; falls back to raw output otherwise). \
        Use ssh_sbom_generate to list all installed packages. Use ssh_compliance_check to audit \
        CIS/STIG configuration controls.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "summarize": {
                "type": "boolean",
                "description": "When true, append an LLM-generated bullet list of the top 3 highest-severity CVEs to the response. Requires the client to advertise the sampling capability; falls back to raw-only output otherwise."
            },
            "summary_max_tokens": {
                "type": "integer",
                "description": "Maximum tokens for the LLM summary (default: 512). Only meaningful with summarize=true.",
                "minimum": 32,
                "maximum": 4096
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

    fn build_command(_args: &SshVulnScanArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SbomCommandBuilder::build_vuln_scan_command())
    }

    /// Optional LLM-side summary appended after the raw output. Falls
    /// back to raw-only when the client does not advertise the
    /// sampling capability.
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
        let prompt = "You are a security analyst. List the top 3 highest-severity CVEs from this vulnerability scan, with CVSS score when available. Bullet points only, one line each, no preamble.";
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

pub type SshVulnScanHandler = StandardToolHandler<VulnScanTool>;

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
        let handler = SshVulnScanHandler::new();
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
        let handler = SshVulnScanHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshVulnScanHandler::new();
        assert_eq!(handler.name(), "ssh_vuln_scan");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "timeout_seconds": 120});
        let args: SshVulnScanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshVulnScanArgs = serde_json::from_value(json).unwrap();
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshVulnScanArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = VulnScanTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("UPGRADABLE"));
        assert!(cmd.contains("KERNEL VERSION"));
        assert!(cmd.contains("PENDING UPDATES"));
    }

    #[tokio::test]
    async fn test_enrich_no_summarize_returns_input() {
        let ctx = create_test_context();
        let args = SshVulnScanArgs {
            host: "h".to_string(),
            summarize: None,
            summary_max_tokens: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text("scan output".to_string());
        let result = VulnScanTool::enrich(base, &args, "scan output", &ctx)
            .await
            .unwrap();
        if let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] {
            assert_eq!(text, "scan output");
        }
    }

    #[tokio::test]
    async fn test_enrich_summarize_without_sampling_falls_back() {
        let ctx = create_test_context();
        let args = SshVulnScanArgs {
            host: "h".to_string(),
            summarize: Some(true),
            summary_max_tokens: Some(256),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text("scan".to_string());
        let result = VulnScanTool::enrich(base, &args, "scan", &ctx)
            .await
            .unwrap();
        if let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] {
            assert!(!text.contains("LLM SUMMARY"));
        }
    }

    #[test]
    fn test_args_debug() {
        let args: SshVulnScanArgs = serde_json::from_value(json!({"host": "h"})).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshVulnScanArgs"));
    }

    #[test]
    fn test_args_summarize_fields() {
        let json = json!({"host": "h", "summarize": true, "summary_max_tokens": 512});
        let args: SshVulnScanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.summarize, Some(true));
        assert_eq!(args.summary_max_tokens, Some(512));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshVulnScanHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 7})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
