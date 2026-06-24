//! SSH Environment Snapshot Tool Handler
//!
//! Captures a comprehensive environment snapshot including OS, packages,
//! services, listeners, users, and config file checksums.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::drift::DriftCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshEnvSnapshotArgs {
    host: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshEnvSnapshotArgs);

#[mcp_standard_tool(name = "ssh_env_snapshot", group = "drift", annotation = "read_only")]
pub struct EnvSnapshotTool;

impl StandardTool for EnvSnapshotTool {
    type Args = SshEnvSnapshotArgs;

    const NAME: &'static str = "ssh_env_snapshot";

    const DESCRIPTION: &'static str = "Capture a comprehensive environment snapshot including \
        OS, packages, services, listeners, users, and config file checksums. Save the output \
        to a local file with save_output for later comparison. Use this as the first step \
        before calling ssh_env_diff (which provides diffing instructions) or to record a \
        baseline for manual comparison. If you only need a one-shot diagnostic without saving \
        files, ssh_compare_state (diagnostics group) covers similar scope. For drift analysis \
        with an automated LLM summary, use ssh_env_drift instead.";

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

    fn build_command(_args: &SshEnvSnapshotArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DriftCommandBuilder::build_snapshot_command())
    }
}

pub type SshEnvSnapshotHandler = StandardToolHandler<EnvSnapshotTool>;

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
        let handler = SshEnvSnapshotHandler::new();
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
        let handler = SshEnvSnapshotHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshEnvSnapshotHandler::new();
        assert_eq!(handler.name(), "ssh_env_snapshot");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "timeout_seconds": 120});
        let args: SshEnvSnapshotArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshEnvSnapshotArgs = serde_json::from_value(json).unwrap();
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshEnvSnapshotArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = EnvSnapshotTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("PACKAGES"));
        assert!(cmd.contains("SERVICES"));
        assert!(cmd.contains("LISTENERS"));
        assert!(cmd.contains("CHECKSUM"));
    }
}
