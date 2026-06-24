//! SSH Backup List Tool Handler
//!
//! Lists contents of tar archives on remote hosts via SSH.
//! Shows files with their sizes and dates.

use serde::Deserialize;
use serde_json::json;

use super::utils::shell_escape;
use crate::config::HostConfig;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshBackupListArgs {
    host: String,
    archive_file: String,
    #[serde(default)]
    verbose: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshBackupListArgs);

#[mcp_standard_tool(name = "ssh_backup_list", group = "backup", annotation = "read_only")]
pub struct BackupListTool;

impl StandardTool for BackupListTool {
    type Args = SshBackupListArgs;

    const NAME: &'static str = "ssh_backup_list";

    const DESCRIPTION: &'static str = "List contents of a tar archive on a remote host via SSH. Returns file paths, sizes, \
        dates, and permissions. Use this to inspect an archive before extracting with \
        ssh_backup_restore. Auto-detects compression format.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "archive_file": {
                "type": "string",
                "description": "Path to the archive file"
            },
            "verbose": {
                "type": "boolean",
                "description": "Show detailed listing with permissions, sizes (default: true)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a file path on the remote host — useful for archives with many files whose listing would be truncated."
            }
        },
        "required": ["host", "archive_file"]
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshBackupListArgs, _host_config: &HostConfig) -> Result<String> {
        let verbose = args.verbose.unwrap_or(true);
        let tar_flag = if verbose { "-tvf" } else { "-tf" };
        Ok(format!(
            "tar {tar_flag} {}",
            shell_escape(&args.archive_file)
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshBackupListArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Backups");
        for h in &parsed.headers {
            tbl = tbl.column(h, h.to_uppercase());
        }
        for row in &parsed.rows {
            let first = row.first().map_or("", String::as_str);
            if first.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            for (i, h) in parsed.headers.iter().enumerate() {
                obj.insert(
                    h.clone(),
                    serde_json::Value::String(row.get(i).map_or_else(String::new, Clone::clone)),
                );
            }
            tbl = tbl.row(serde_json::Value::Object(obj));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_backup_list",
            Some(json!({"host": args.host, "archive_file": args.archive_file})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_backup_list` tool.
pub type SshBackupListHandler = StandardToolHandler<BackupListTool>;

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
        let handler = SshBackupListHandler::new();
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
        let handler = SshBackupListHandler::new();
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
        let handler = SshBackupListHandler::new();
        assert_eq!(handler.name(), "ssh_backup_list");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_backup_list");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("archive_file")));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshBackupListHandler::new();
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("verbose"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "archive_file": "/tmp/backup.tar.gz",
            "verbose": true,
            "timeout_seconds": 120,
            "max_output": 50000
        });

        let args: SshBackupListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.archive_file, "/tmp/backup.tar.gz");
        assert_eq!(args.verbose, Some(true));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(50000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "archive_file": "/tmp/backup.tar"
        });

        let args: SshBackupListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.archive_file, "/tmp/backup.tar");
        // verbose defaults to None (build_command treats None as true)
        assert!(args.verbose.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_args_with_all_options() {
        let json = json!({
            "host": "prod-server",
            "archive_file": "/backups/full-backup.tar.xz",
            "verbose": false,
            "timeout_seconds": 300,
            "max_output": 100_000
        });

        let args: SshBackupListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "prod-server");
        assert_eq!(args.archive_file, "/backups/full-backup.tar.xz");
        assert_eq!(args.verbose, Some(false));
        assert_eq!(args.timeout_seconds, Some(300));
        assert_eq!(args.max_output, Some(100_000));
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
    fn test_build_command_verbose_true() {
        let args = SshBackupListArgs {
            host: "server1".to_string(),
            archive_file: "/tmp/backup.tar".to_string(),
            verbose: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupListTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "tar -tvf '/tmp/backup.tar'");
    }

    #[test]
    fn test_build_command_verbose_false() {
        let args = SshBackupListArgs {
            host: "server1".to_string(),
            archive_file: "/tmp/backup.tar".to_string(),
            verbose: Some(false),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupListTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "tar -tf '/tmp/backup.tar'");
    }

    #[test]
    fn test_build_command_verbose_default() {
        let args = SshBackupListArgs {
            host: "server1".to_string(),
            archive_file: "/tmp/backup.tar.gz".to_string(),
            verbose: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupListTool::build_command(&args, &host_config).unwrap();
        // Default verbose is true
        assert_eq!(cmd, "tar -tvf '/tmp/backup.tar.gz'");
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "test-host",
            "archive_file": "/tmp/backup.tar"
        });

        let args: SshBackupListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshBackupListArgs"));
        assert!(debug_str.contains("test-host"));
    }
}
