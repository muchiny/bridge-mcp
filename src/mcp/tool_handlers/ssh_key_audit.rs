//! Handler for the `ssh_key_audit` tool.
//!
//! Audits SSH authorized keys on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::key_management::KeyManagementCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshKeyAuditArgs {
    /// Target host name from configuration.
    host: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshKeyAuditArgs);

#[mcp_standard_tool(
    name = "ssh_key_audit",
    group = "key_management",
    annotation = "read_only"
)]
pub struct KeyAuditTool;

impl StandardTool for KeyAuditTool {
    type Args = SshKeyAuditArgs;

    const NAME: &'static str = "ssh_key_audit";

    const DESCRIPTION: &'static str = "Audit the ~/.ssh/authorized_keys file of the user the bridge \
        connects as on the target host. Shows key count, types, comments, and file permissions. \
        Scope: SSH authorized key management only — for broader security hardening checks use \
        ssh_security_audit; for CIS benchmark compliance use ssh_compliance_check. To audit other \
        users' authorized keys, use ssh_exec with sudo per-user. Output size scales with number of \
        keys; pass save_output for hosts with many authorized keys (e.g. CI jump boxes).";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(_args: &SshKeyAuditArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(KeyManagementCommandBuilder::build_key_audit_command())
    }
}

/// Handler for the `ssh_key_audit` tool.
pub type SshKeyAuditHandler = StandardToolHandler<KeyAuditTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshKeyAuditHandler::new();
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
        let handler = SshKeyAuditHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshKeyAuditHandler::new();
        assert_eq!(handler.name(), "ssh_key_audit");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_key_audit");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "timeout_seconds": 30,
            "max_output": 10000,
            "save_output": "/tmp/audit.txt"
        });
        let args: SshKeyAuditArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/audit.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshKeyAuditArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshKeyAuditHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshKeyAuditArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshKeyAuditArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshKeyAuditHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: AuthConfig::Agent,
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

    #[test]
    fn test_build_command() {
        let args = SshKeyAuditArgs {
            host: "s".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = KeyAuditTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("SSH Key Audit"));
        assert!(cmd.contains("authorized_keys"));
        assert!(cmd.contains("Key Types"));
    }

    #[test]
    fn test_build_command_checks_file() {
        let args = SshKeyAuditArgs {
            host: "s".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = KeyAuditTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("if [ -f ~/.ssh/authorized_keys ]"));
    }
}
