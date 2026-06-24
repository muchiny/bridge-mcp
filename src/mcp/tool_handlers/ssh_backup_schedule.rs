//! Handler for the `ssh_backup_schedule` tool.
//!
//! Schedules a periodic backup via cron on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::backup_advanced::BackupAdvancedCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshBackupScheduleArgs {
    /// Target host name from configuration.
    host: String,
    /// Cron schedule expression (e.g., "0 2 * * *").
    cron_expr: String,
    /// Paths to back up (space-separated).
    paths: String,
    /// Destination directory for backup archives.
    dest: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshBackupScheduleArgs);

#[mcp_standard_tool(
    name = "ssh_backup_schedule",
    group = "backup",
    annotation = "mutating"
)]
pub struct BackupScheduleTool;

impl StandardTool for BackupScheduleTool {
    type Args = SshBackupScheduleArgs;

    const NAME: &'static str = "ssh_backup_schedule";

    const DESCRIPTION: &'static str = "Schedule a periodic backup via cron on a remote host (Linux only). \
        Adds a cron job that creates timestamped gzip-compressed tar archives (always .tar.gz — \
        compression is fixed and cannot be changed) of the specified paths in the destination directory. \
        Pass paths as a single space-separated string — unlike ssh_backup_create which takes an array. \
        Use ssh_cron_list to verify the schedule was added. Specify the schedule in standard 5-field \
        cron format (e.g., '0 2 * * *' for daily at 2am).";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "cron_expr": {
                        "type": "string",
                        "description": "Cron schedule expression (e.g., '0 2 * * *' for daily at 2am)"
                    },
                    "paths": {
                        "type": "string",
                        "description": "Paths to back up as a single space-separated string (e.g., '/var/data /etc/config'). Unlike ssh_backup_create which takes an array, this tool accepts a plain string."
                    },
                    "dest": {
                        "type": "string",
                        "description": "Destination directory for backup archives"
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
                "required": ["host", "cron_expr", "paths", "dest"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshBackupScheduleArgs, _host_config: &HostConfig) -> Result<String> {
        BackupAdvancedCommandBuilder::build_schedule_command(
            &args.cron_expr,
            &args.paths,
            &args.dest,
        )
    }
}

/// Handler for the `ssh_backup_schedule` tool.
pub type SshBackupScheduleHandler = StandardToolHandler<BackupScheduleTool>;

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
        let handler = SshBackupScheduleHandler::new();
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
        let handler = SshBackupScheduleHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "cron_expr": "0 2 * * *",
                    "paths": "/var/data",
                    "dest": "/backups"
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
        let handler = SshBackupScheduleHandler::new();
        assert_eq!(handler.name(), "ssh_backup_schedule");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_backup_schedule");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("cron_expr")));
        assert!(required.contains(&json!("paths")));
        assert!(required.contains(&json!("dest")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "cron_expr": "0 2 * * *",
            "paths": "/var/data /etc/config",
            "dest": "/backups",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/schedule.txt"
        });
        let args: SshBackupScheduleArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.cron_expr, "0 2 * * *");
        assert_eq!(args.paths, "/var/data /etc/config");
        assert_eq!(args.dest, "/backups");
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "cron_expr": "0 * * * *",
            "paths": "/var/data",
            "dest": "/backups"
        });
        let args: SshBackupScheduleArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshBackupScheduleHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "cron_expr": "0 * * * *",
            "paths": "/data",
            "dest": "/backups"
        });
        let args: SshBackupScheduleArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshBackupScheduleArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshBackupScheduleHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": 123,
                    "cron_expr": 456,
                    "paths": 789,
                    "dest": 0
                })),
                &ctx,
            )
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
        let args = SshBackupScheduleArgs {
            host: "s".to_string(),
            cron_expr: "0 2 * * *".to_string(),
            paths: "/var/data".to_string(),
            dest: "/backups".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = BackupScheduleTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("crontab"));
        assert!(cmd.contains("0 2 * * *"));
    }

    #[test]
    fn test_build_command_invalid_cron() {
        let args = SshBackupScheduleArgs {
            host: "s".to_string(),
            cron_expr: "bad".to_string(),
            paths: "/var/data".to_string(),
            dest: "/backups".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = BackupScheduleTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
