//! Handler for the `ssh_backup_verify` tool.
//!
//! Verifies the integrity of a backup archive on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::backup_advanced::BackupAdvancedCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshBackupVerifyArgs {
    /// Target host name from configuration.
    host: String,
    /// Path to the archive to verify.
    archive: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshBackupVerifyArgs);

#[mcp_standard_tool(name = "ssh_backup_verify", group = "backup", annotation = "read_only")]
pub struct BackupVerifyTool;

impl StandardTool for BackupVerifyTool {
    type Args = SshBackupVerifyArgs;

    const NAME: &'static str = "ssh_backup_verify";

    const DESCRIPTION: &'static str = "Verify the integrity of a backup archive on a remote host. \
        Tests that the tar archive is readable, displays its SHA-256 checksum, lists the first \
        20 entries, and shows the archive size. Use this after ssh_backup_snapshot or \
        ssh_backup_create to confirm archive integrity.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "archive": {
                        "type": "string",
                        "description": "Path to the archive file to verify (must contain .tar)"
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
                "required": ["host", "archive"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshBackupVerifyArgs, _host_config: &HostConfig) -> Result<String> {
        BackupAdvancedCommandBuilder::build_verify_command(&args.archive)
    }
}

/// Handler for the `ssh_backup_verify` tool.
pub type SshBackupVerifyHandler = StandardToolHandler<BackupVerifyTool>;

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
        let handler = SshBackupVerifyHandler::new();
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
        let handler = SshBackupVerifyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "archive": "/tmp/backup.tar.gz"})),
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
        let handler = SshBackupVerifyHandler::new();
        assert_eq!(handler.name(), "ssh_backup_verify");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_backup_verify");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("archive")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "archive": "/tmp/backup.tar.gz",
            "timeout_seconds": 60,
            "max_output": 10000,
            "save_output": "/tmp/verify.txt"
        });
        let args: SshBackupVerifyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.archive, "/tmp/backup.tar.gz");
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "archive": "/tmp/backup.tar.gz"});
        let args: SshBackupVerifyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.archive, "/tmp/backup.tar.gz");
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshBackupVerifyHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "archive": "/tmp/backup.tar.gz"});
        let args: SshBackupVerifyArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshBackupVerifyArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshBackupVerifyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "archive": 456})), &ctx)
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
    fn test_build_command_valid() {
        let args = SshBackupVerifyArgs {
            host: "s".to_string(),
            archive: "/tmp/backup.tar.gz".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = BackupVerifyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("tar tzf"));
        assert!(cmd.contains("Archive OK"));
        assert!(cmd.contains("sha256sum"));
    }

    #[test]
    fn test_build_command_invalid_archive() {
        let args = SshBackupVerifyArgs {
            host: "s".to_string(),
            archive: "/tmp/backup.zip".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = BackupVerifyTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
