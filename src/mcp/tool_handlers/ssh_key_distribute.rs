//! Handler for the `ssh_key_distribute` tool.
//!
//! Distributes (appends) an SSH public key to a remote host's `authorized_keys`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::key_management::KeyManagementCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshKeyDistributeArgs {
    /// Target host name from configuration.
    host: String,
    /// SSH public key to distribute (e.g., "ssh-ed25519 AAAA... user@host").
    public_key: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshKeyDistributeArgs);

#[mcp_standard_tool(
    name = "ssh_key_distribute",
    group = "key_management",
    annotation = "mutating_idempotent"
)]
pub struct KeyDistributeTool;

impl StandardTool for KeyDistributeTool {
    type Args = SshKeyDistributeArgs;

    const NAME: &'static str = "ssh_key_distribute";

    const DESCRIPTION: &'static str = "Distribute an SSH public key to a remote host. Appends the \
        key to ~/.ssh/authorized_keys if not already present. Creates the .ssh directory and \
        sets correct permissions. Use ssh_key_generate to create a key pair first, then \
        distribute the public key.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "public_key": {
                        "type": "string",
                        "description": "Full SSH public key string as it appears in a .pub file or as returned by ssh_key_generate — must include the algorithm prefix (e.g., 'ssh-ed25519 AAAA... user@host' or 'ssh-rsa AAAA... user@host'). Passing only the key material without the prefix will be rejected."
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
                "required": ["host", "public_key"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshKeyDistributeArgs, _host_config: &HostConfig) -> Result<String> {
        KeyManagementCommandBuilder::build_key_distribute_command(&args.public_key)
    }
}

/// Handler for the `ssh_key_distribute` tool.
pub type SshKeyDistributeHandler = StandardToolHandler<KeyDistributeTool>;

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
        let handler = SshKeyDistributeHandler::new();
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
        let handler = SshKeyDistributeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host"
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshKeyDistributeHandler::new();
        assert_eq!(handler.name(), "ssh_key_distribute");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_key_distribute");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("public_key")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/distribute.txt"
        });
        let args: SshKeyDistributeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.public_key.starts_with("ssh-ed25519"));
        assert_eq!(args.timeout_seconds, Some(15));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ user@host"
        });
        let args: SshKeyDistributeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.public_key.starts_with("ssh-rsa"));
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshKeyDistributeHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host"
        });
        let args: SshKeyDistributeArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshKeyDistributeArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshKeyDistributeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "public_key": 456})), &ctx)
            .await;
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
    fn test_build_command_valid_key() {
        let args = SshKeyDistributeArgs {
            host: "s".to_string(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = KeyDistributeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("authorized_keys"));
        assert!(cmd.contains("grep -qF"));
        assert!(cmd.contains("mkdir -p"));
    }

    #[test]
    fn test_build_command_invalid_key() {
        let args = SshKeyDistributeArgs {
            host: "s".to_string(),
            public_key: "not-a-valid-key".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = KeyDistributeTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
