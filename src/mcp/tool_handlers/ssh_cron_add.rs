//! Handler for the `ssh_cron_add` tool.
//!
//! Adds a cron job on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::cron::CronCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshCronAddArgs {
    /// Target host name from configuration.
    host: String,
    /// Cron schedule expression (e.g., "0 2 * * *").
    schedule: String,
    /// Command to run on the cron schedule.
    command: String,
    /// User whose crontab to modify.
    user: Option<String>,
    /// Comment to add above the cron entry.
    comment: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshCronAddArgs);

#[mcp_standard_tool(name = "ssh_cron_add", group = "cron", annotation = "mutating")]
pub struct CronAddTool;

impl StandardTool for CronAddTool {
    type Args = SshCronAddArgs;

    const NAME: &'static str = "ssh_cron_add";

    const DESCRIPTION: &'static str = "Add a cron job on a remote host. Prefer this over ssh_exec as it safely appends to \
        the existing crontab without overwriting. Specify the schedule in cron format (e.g., \
        '0 2 * * *' for daily at 2am) and the command to run. For backup-specific scheduling \
        with built-in tar/retention logic, prefer ssh_backup_schedule instead. Verify with \
        ssh_cron_list afterward.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "schedule": {
                        "type": "string",
                        "description": "Cron schedule expression (e.g., '0 2 * * *')"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to run on the cron schedule"
                    },
                    "user": {
                        "type": "string",
                        "description": "User whose crontab to modify (default: the SSH user configured for this host). Modifying another user's crontab requires the SSH user to have sudo/root privileges."
                    },
                    "comment": {
                        "type": "string",
                        "description": "Comment to add above the cron entry"
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
                "required": ["host", "schedule", "command"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshCronAddArgs, _host_config: &HostConfig) -> Result<String> {
        CronCommandBuilder::build_add_command(
            &args.schedule,
            &args.command,
            args.user.as_deref(),
            args.comment.as_deref(),
        )
    }
}

/// Handler for the `ssh_cron_add` tool.
pub type SshCronAddHandler = StandardToolHandler<CronAddTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCronAddHandler::new();
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
        let handler = SshCronAddHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "schedule": "0 2 * * *",
                    "command": "/usr/bin/backup.sh"
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
        let handler = SshCronAddHandler::new();
        assert_eq!(handler.name(), "ssh_cron_add");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_cron_add");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("schedule")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "schedule": "0 2 * * *",
            "command": "/usr/bin/backup.sh",
            "user": "root",
            "comment": "Nightly backup",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/cron_add.txt"
        });
        let args: SshCronAddArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.schedule, "0 2 * * *");
        assert_eq!(args.command, "/usr/bin/backup.sh");
        assert_eq!(args.user.as_deref(), Some("root"));
        assert_eq!(args.comment.as_deref(), Some("Nightly backup"));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/cron_add.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "schedule": "*/5 * * * *",
            "command": "echo hello"
        });
        let args: SshCronAddArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.schedule, "*/5 * * * *");
        assert_eq!(args.command, "echo hello");
        assert!(args.user.is_none());
        assert!(args.comment.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCronAddHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("user"));
        assert!(props.contains_key("comment"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "schedule": "0 * * * *",
            "command": "date"
        });
        let args: SshCronAddArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCronAddArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCronAddHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "schedule": 456, "command": 789})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    use crate::config::{HostConfig, HostKeyVerification, OsType};

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
    fn test_build_command_defaults() {
        let args = SshCronAddArgs {
            host: "s".to_string(),
            schedule: "0 2 * * *".to_string(),
            command: "/usr/bin/backup.sh".to_string(),
            user: None,
            comment: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CronAddTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("0 2 * * *"));
        assert!(cmd.contains("/usr/bin/backup.sh"));
    }

    #[test]
    fn test_build_command_with_user() {
        let args = SshCronAddArgs {
            host: "s".to_string(),
            schedule: "*/5 * * * *".to_string(),
            command: "echo hello".to_string(),
            user: Some("www-data".to_string()),
            comment: Some("health check".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CronAddTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("*/5 * * * *"));
        assert!(cmd.contains("echo hello"));
    }
}
