//! Handler for the `ssh_key_generate` tool.
//!
//! Generates a new SSH key pair on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::key_management::KeyManagementCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshKeyGenerateArgs {
    /// Target host name from configuration.
    host: String,
    /// Key type (ed25519, rsa, ecdsa). Defaults to ed25519.
    #[serde(default)]
    key_type: Option<String>,
    /// Key bit length (only for rsa/ecdsa).
    #[serde(default)]
    bits: Option<u32>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshKeyGenerateArgs);

#[mcp_standard_tool(
    name = "ssh_key_generate",
    group = "key_management",
    annotation = "mutating"
)]
pub struct KeyGenerateTool;

impl StandardTool for KeyGenerateTool {
    type Args = SshKeyGenerateArgs;

    const NAME: &'static str = "ssh_key_generate";

    const DESCRIPTION: &'static str = "Generate a new SSH key pair on a remote host. The key is \
        created at /tmp/mcp_generated_key with an empty passphrase. Supports ed25519 (default), \
        rsa, and ecdsa key types. Returns the public key and fingerprint.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "key_type": {
                        "type": "string",
                        "enum": ["ed25519", "rsa", "ecdsa"],
                        "description": "Key type (default: ed25519)"
                    },
                    "bits": {
                        "type": "integer",
                        "description": "Key bit length. Ignored for ed25519 (fixed-length). For ecdsa, use 256, 384, or 521. For RSA, recommended minimum 2048; use 3072 or 4096 for long-lived keys.",
                        "minimum": 256,
                        "maximum": 16384
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

    fn build_command(args: &SshKeyGenerateArgs, _host_config: &HostConfig) -> Result<String> {
        KeyManagementCommandBuilder::build_key_generate_command(args.key_type.as_deref(), args.bits)
    }
}

/// Handler for the `ssh_key_generate` tool.
pub type SshKeyGenerateHandler = StandardToolHandler<KeyGenerateTool>;

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
        let handler = SshKeyGenerateHandler::new();
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
        let handler = SshKeyGenerateHandler::new();
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
        let handler = SshKeyGenerateHandler::new();
        assert_eq!(handler.name(), "ssh_key_generate");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_key_generate");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "key_type": "rsa",
            "bits": 4096,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/keygen.txt"
        });
        let args: SshKeyGenerateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.key_type.as_deref(), Some("rsa"));
        assert_eq!(args.bits, Some(4096));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshKeyGenerateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.key_type.is_none());
        assert!(args.bits.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshKeyGenerateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("key_type"));
        assert!(props.contains_key("bits"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshKeyGenerateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshKeyGenerateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshKeyGenerateHandler::new();
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
    fn test_build_command_defaults() {
        let args = SshKeyGenerateArgs {
            host: "s".to_string(),
            key_type: None,
            bits: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = KeyGenerateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ssh-keygen"));
        assert!(cmd.contains("ed25519"));
    }

    #[test]
    fn test_build_command_rsa_with_bits() {
        let args = SshKeyGenerateArgs {
            host: "s".to_string(),
            key_type: Some("rsa".to_string()),
            bits: Some(4096),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = KeyGenerateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("rsa"));
        assert!(cmd.contains("-b 4096"));
    }
}
