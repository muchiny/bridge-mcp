//! SSH Backup Restore Tool Handler
//!
//! Restores/extracts files from tar archives on remote hosts via SSH.
//! Supports extracting to a specific directory and stripping path components.

use serde::Deserialize;

use super::utils::shell_escape;
use crate::config::HostConfig;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshBackupRestoreArgs {
    host: String,
    archive_file: String,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    strip_components: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshBackupRestoreArgs);

#[mcp_standard_tool(name = "ssh_backup_restore", group = "backup", annotation = "destructive")]
pub struct BackupRestoreTool;

impl StandardTool for BackupRestoreTool {
    type Args = SshBackupRestoreArgs;

    const NAME: &'static str = "ssh_backup_restore";

    const DESCRIPTION: &'static str = "Extract files from a tar archive on a remote host via SSH. Supports extracting to a \
        specific destination directory and stripping leading path components. Auto-detects \
        compression format. Use ssh_backup_list first to inspect the archive contents before \
        extracting.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "archive_file": {
                "type": "string",
                "description": "Path to the archive file to restore"
            },
            "destination": {
                "type": "string",
                "description": "Directory to extract to (default: current directory). Uses tar -C flag."
            },
            "strip_components": {
                "type": "integer",
                "description": "Strip N leading path components (tar --strip-components)",
                "minimum": 0
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["host", "archive_file"]
    }"#;

    fn build_command(args: &SshBackupRestoreArgs, _host_config: &HostConfig) -> Result<String> {
        let mut parts = vec![format!("tar -xf {}", shell_escape(&args.archive_file))];
        if let Some(ref dest) = args.destination {
            parts.push(format!("-C {}", shell_escape(dest)));
        }
        if let Some(strip) = args.strip_components {
            parts.push(format!("--strip-components={strip}"));
        }
        let tar_cmd = parts.join(" ");
        if let Some(ref dest) = args.destination {
            Ok(format!("{tar_cmd} && ls -la {}", shell_escape(dest)))
        } else {
            Ok(tar_cmd)
        }
    }
}

/// Handler for the `ssh_backup_restore` tool.
pub type SshBackupRestoreHandler = StandardToolHandler<BackupRestoreTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshBackupRestoreHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshBackupRestoreHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "archive_file": "/tmp/backup.tar"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "nonexistent");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshBackupRestoreHandler::new();
        assert_eq!(handler.name(), "ssh_backup_restore");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_backup_restore");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("archive_file")));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshBackupRestoreHandler::new();
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("destination"));
        assert!(properties.contains_key("strip_components"));
        assert!(properties.contains_key("timeout_seconds"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "archive_file": "/tmp/backup.tar.gz",
            "destination": "/opt/restore",
            "strip_components": 1,
            "timeout_seconds": 300
        });

        let args: SshBackupRestoreArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.archive_file, "/tmp/backup.tar.gz");
        assert_eq!(args.destination, Some("/opt/restore".to_string()));
        assert_eq!(args.strip_components, Some(1));
        assert_eq!(args.timeout_seconds, Some(300));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "archive_file": "/tmp/backup.tar"
        });

        let args: SshBackupRestoreArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.archive_file, "/tmp/backup.tar");
        assert!(args.destination.is_none());
        assert!(args.strip_components.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_args_with_all_options() {
        let json = json!({
            "host": "prod-server",
            "archive_file": "/backups/full-backup.tar.xz",
            "destination": "/var/www/restored",
            "strip_components": 2,
            "timeout_seconds": 1800
        });

        let args: SshBackupRestoreArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "prod-server");
        assert_eq!(args.archive_file, "/backups/full-backup.tar.xz");
        assert_eq!(args.destination, Some("/var/www/restored".to_string()));
        assert_eq!(args.strip_components, Some(2));
        assert_eq!(args.timeout_seconds, Some(1800));
    }

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

    #[test]
    fn test_build_command_basic() {
        let args = SshBackupRestoreArgs {
            host: "server1".to_string(),
            archive_file: "/tmp/backup.tar".to_string(),
            destination: None,
            strip_components: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupRestoreTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "tar -xf '/tmp/backup.tar'");
    }

    #[test]
    fn test_build_command_with_destination() {
        let args = SshBackupRestoreArgs {
            host: "server1".to_string(),
            archive_file: "/tmp/backup.tar".to_string(),
            destination: Some("/opt/restore".to_string()),
            strip_components: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupRestoreTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("tar -xf '/tmp/backup.tar' -C '/opt/restore'"));
        assert!(cmd.contains("&& ls -la '/opt/restore'"));
    }

    #[test]
    fn test_build_command_with_strip_components() {
        let args = SshBackupRestoreArgs {
            host: "server1".to_string(),
            archive_file: "/tmp/backup.tar".to_string(),
            destination: None,
            strip_components: Some(2),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupRestoreTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("--strip-components=2"));
        // No ls appended when no destination
        assert!(!cmd.contains("&& ls"));
    }

    #[test]
    fn test_build_command_with_all_options() {
        let args = SshBackupRestoreArgs {
            host: "server1".to_string(),
            archive_file: "/tmp/backup.tar.gz".to_string(),
            destination: Some("/opt/restore".to_string()),
            strip_components: Some(1),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupRestoreTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("tar -xf '/tmp/backup.tar.gz'"));
        assert!(cmd.contains("-C '/opt/restore'"));
        assert!(cmd.contains("--strip-components=1"));
        assert!(cmd.contains("&& ls -la '/opt/restore'"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "test-host",
            "archive_file": "/tmp/backup.tar"
        });

        let args: SshBackupRestoreArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshBackupRestoreArgs"));
        assert!(debug_str.contains("test-host"));
    }
}
