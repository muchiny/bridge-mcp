//! Handler for the `ssh_backup_snapshot` tool.
//!
//! Creates a timestamped snapshot archive of specified paths on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::backup_advanced::BackupAdvancedCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshBackupSnapshotArgs {
    /// Target host name from configuration.
    host: String,
    /// Paths to include in the snapshot (space-separated).
    paths: String,
    /// Label for the snapshot (used in filename).
    #[serde(default)]
    label: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshBackupSnapshotArgs);

#[mcp_standard_tool(
    name = "ssh_backup_snapshot",
    group = "backup",
    annotation = "mutating"
)]
pub struct BackupSnapshotTool;

impl StandardTool for BackupSnapshotTool {
    type Args = SshBackupSnapshotArgs;

    const NAME: &'static str = "ssh_backup_snapshot";

    const DESCRIPTION: &'static str = "Create a timestamped gzip-compressed tar archive of specified \
        paths on a remote host (Linux only). The archive is saved to /tmp/ with a timestamp and optional \
        label; the tool returns the archive path, size, and SHA-256 checksum. Pass paths as a single \
        space-separated string (e.g., '/var/data /etc/config') — unlike ssh_backup_create which takes \
        an array. Use ssh_backup_verify to validate the archive afterward, or ssh_backup_list to \
        inspect its contents.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "paths": {
                        "type": "string",
                        "description": "Paths to include in the snapshot as a single space-separated string (e.g., '/var/data /etc/config'). Unlike ssh_backup_create which takes an array, this tool accepts a plain string."
                    },
                    "label": {
                        "type": "string",
                        "description": "Label for the snapshot (used in filename, e.g., 'pre-deploy')"
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
                "required": ["host", "paths"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshBackupSnapshotArgs, _host_config: &HostConfig) -> Result<String> {
        BackupAdvancedCommandBuilder::build_snapshot_command(&args.paths, args.label.as_deref())
    }
}

/// Handler for the `ssh_backup_snapshot` tool.
pub type SshBackupSnapshotHandler = StandardToolHandler<BackupSnapshotTool>;

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
        let handler = SshBackupSnapshotHandler::new();
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
        let handler = SshBackupSnapshotHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "paths": "/var/data"})),
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
        let handler = SshBackupSnapshotHandler::new();
        assert_eq!(handler.name(), "ssh_backup_snapshot");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_backup_snapshot");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("paths")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "paths": "/var/data /etc/config",
            "label": "pre-deploy",
            "timeout_seconds": 120,
            "max_output": 5000,
            "save_output": "/tmp/snapshot.txt"
        });
        let args: SshBackupSnapshotArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.paths, "/var/data /etc/config");
        assert_eq!(args.label.as_deref(), Some("pre-deploy"));
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "paths": "/var/data"});
        let args: SshBackupSnapshotArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.paths, "/var/data");
        assert!(args.label.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshBackupSnapshotHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("label"));
        assert!(props.contains_key("timeout_seconds"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "paths": "/data"});
        let args: SshBackupSnapshotArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshBackupSnapshotArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshBackupSnapshotHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "paths": 456})), &ctx)
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
    fn test_build_command_defaults() {
        let args = SshBackupSnapshotArgs {
            host: "s".to_string(),
            paths: "/var/data".to_string(),
            label: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = BackupSnapshotTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("tar czf"));
        assert!(cmd.contains("sha256sum"));
        assert!(cmd.contains("snapshot"));
    }

    #[test]
    fn test_build_command_with_label() {
        let args = SshBackupSnapshotArgs {
            host: "s".to_string(),
            paths: "/var/data".to_string(),
            label: Some("pre-deploy".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = BackupSnapshotTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("pre-deploy"));
    }
}
