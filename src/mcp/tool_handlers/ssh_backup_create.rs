//! SSH Backup Create Tool Handler
//!
//! Creates tar archive backups of files/directories on remote hosts via SSH.
//! Supports gzip, bzip2, and xz compression.

use serde::Deserialize;

use super::utils::shell_escape;
use crate::config::HostConfig;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshBackupCreateArgs {
    host: String,
    source_paths: Vec<String>,
    output_file: String,
    #[serde(default)]
    compress: Option<String>,
    #[serde(default)]
    exclude: Option<Vec<String>>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshBackupCreateArgs);

#[mcp_standard_tool(name = "ssh_backup_create", group = "backup", annotation = "mutating")]
pub struct BackupCreateTool;

impl StandardTool for BackupCreateTool {
    type Args = SshBackupCreateArgs;

    const NAME: &'static str = "ssh_backup_create";

    const DESCRIPTION: &'static str = "Create a tar archive backup of files/directories on a remote host via SSH. \
        Supports gzip, bzip2, and xz compression (default: none). Provide source paths as a JSON array \
        (source_paths) — unlike ssh_backup_snapshot and ssh_backup_schedule which take a space-separated \
        string. The archive is written on the remote host at output_file; use ssh_backup_list to verify \
        contents, ssh_backup_restore to extract, or ssh_download to retrieve the archive locally. \
        For a quick one-off snapshot with auto-timestamping use ssh_backup_snapshot instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "source_paths": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Paths to include in the archive"
            },
            "output_file": {
                "type": "string",
                "description": "Path for the output archive file"
            },
            "compress": {
                "type": "string",
                "enum": ["gzip", "bzip2", "xz"],
                "description": "Compression type (default: none)"
            },
            "exclude": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Patterns to exclude (passed as --exclude=pattern)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a file path on the remote host — useful when archiving large directory trees whose verbose listing would be truncated."
            }
        },
        "required": ["host", "source_paths", "output_file"]
    }"#;

    fn build_command(args: &SshBackupCreateArgs, _host_config: &HostConfig) -> Result<String> {
        let tar_flag = match args.compress.as_deref() {
            Some("gzip") => "-czf",
            Some("bzip2") => "-cjf",
            Some("xz") => "-cJf",
            _ => "-cf",
        };
        let mut parts = vec![format!(
            "tar {tar_flag} {}",
            shell_escape(&args.output_file)
        )];
        if let Some(ref excludes) = args.exclude {
            for pattern in excludes {
                parts.push(format!("--exclude={}", shell_escape(pattern)));
            }
        }
        for path in &args.source_paths {
            parts.push(shell_escape(path));
        }
        let tar_cmd = parts.join(" ");
        Ok(format!(
            "{tar_cmd} && ls -lh {}",
            shell_escape(&args.output_file)
        ))
    }
}

/// Handler for the `ssh_backup_create` tool.
pub type SshBackupCreateHandler = StandardToolHandler<BackupCreateTool>;

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
        let handler = SshBackupCreateHandler::new();
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
        let handler = SshBackupCreateHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "source_paths": ["/home/user/data"],
                    "output_file": "/tmp/backup.tar"
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
        let handler = SshBackupCreateHandler::new();
        assert_eq!(handler.name(), "ssh_backup_create");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_backup_create");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("source_paths")));
        assert!(required.contains(&json!("output_file")));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshBackupCreateHandler::new();
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("compress"));
        assert!(properties.contains_key("exclude"));
        assert!(properties.contains_key("timeout_seconds"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "source_paths": ["/home/user/data", "/etc/config"],
            "output_file": "/tmp/backup.tar.gz",
            "compress": "gzip",
            "exclude": ["*.log", "*.tmp"],
            "timeout_seconds": 600
        });

        let args: SshBackupCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(
            args.source_paths,
            vec!["/home/user/data".to_string(), "/etc/config".to_string()]
        );
        assert_eq!(args.output_file, "/tmp/backup.tar.gz");
        assert_eq!(args.compress, Some("gzip".to_string()));
        assert_eq!(
            args.exclude,
            Some(vec!["*.log".to_string(), "*.tmp".to_string()])
        );
        assert_eq!(args.timeout_seconds, Some(600));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "source_paths": ["/home/user/data"],
            "output_file": "/tmp/backup.tar"
        });

        let args: SshBackupCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.source_paths, vec!["/home/user/data".to_string()]);
        assert_eq!(args.output_file, "/tmp/backup.tar");
        assert!(args.compress.is_none());
        assert!(args.exclude.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_args_with_all_options() {
        let json = json!({
            "host": "prod-server",
            "source_paths": ["/var/www", "/etc/nginx", "/opt/app"],
            "output_file": "/backups/full-backup.tar.xz",
            "compress": "xz",
            "exclude": ["*.log", "*.pid", "node_modules"],
            "timeout_seconds": 1800
        });

        let args: SshBackupCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "prod-server");
        assert_eq!(args.source_paths.len(), 3);
        assert_eq!(args.compress, Some("xz".to_string()));
        assert_eq!(args.exclude.as_ref().unwrap().len(), 3);
        assert_eq!(args.timeout_seconds, Some(1800));
    }

    #[test]
    fn test_args_invalid_compress_value() {
        // Invalid compress value is just a string - validation happens at command build time
        let json = json!({
            "host": "server1",
            "source_paths": ["/data"],
            "output_file": "/tmp/backup.tar",
            "compress": "lz4"
        });

        let args: SshBackupCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.compress, Some("lz4".to_string()));
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
    fn test_build_command_no_compression() {
        let args = SshBackupCreateArgs {
            host: "server1".to_string(),
            source_paths: vec!["/home/user/data".to_string()],
            output_file: "/tmp/backup.tar".to_string(),
            compress: None,
            exclude: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupCreateTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.starts_with("tar -cf"));
        assert!(cmd.contains("'/tmp/backup.tar'"));
        assert!(cmd.contains("'/home/user/data'"));
        assert!(cmd.contains("&& ls -lh"));
    }

    #[test]
    fn test_build_command_gzip() {
        let args = SshBackupCreateArgs {
            host: "server1".to_string(),
            source_paths: vec!["/data".to_string()],
            output_file: "/tmp/backup.tar.gz".to_string(),
            compress: Some("gzip".to_string()),
            exclude: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupCreateTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.starts_with("tar -czf"));
    }

    #[test]
    fn test_build_command_bzip2() {
        let args = SshBackupCreateArgs {
            host: "server1".to_string(),
            source_paths: vec!["/data".to_string()],
            output_file: "/tmp/backup.tar.bz2".to_string(),
            compress: Some("bzip2".to_string()),
            exclude: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupCreateTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.starts_with("tar -cjf"));
    }

    #[test]
    fn test_build_command_xz() {
        let args = SshBackupCreateArgs {
            host: "server1".to_string(),
            source_paths: vec!["/data".to_string()],
            output_file: "/tmp/backup.tar.xz".to_string(),
            compress: Some("xz".to_string()),
            exclude: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupCreateTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.starts_with("tar -cJf"));
    }

    #[test]
    fn test_build_command_with_excludes() {
        let args = SshBackupCreateArgs {
            host: "server1".to_string(),
            source_paths: vec!["/data".to_string()],
            output_file: "/tmp/backup.tar".to_string(),
            compress: None,
            exclude: Some(vec!["*.log".to_string(), "*.tmp".to_string()]),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupCreateTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("--exclude='*.log'"));
        assert!(cmd.contains("--exclude='*.tmp'"));
    }

    #[test]
    fn test_build_command_multiple_sources() {
        let args = SshBackupCreateArgs {
            host: "server1".to_string(),
            source_paths: vec![
                "/var/www".to_string(),
                "/etc/nginx".to_string(),
                "/opt/app".to_string(),
            ],
            output_file: "/tmp/backup.tar".to_string(),
            compress: None,
            exclude: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let host_config = test_host_config();
        let cmd = BackupCreateTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("'/var/www'"));
        assert!(cmd.contains("'/etc/nginx'"));
        assert!(cmd.contains("'/opt/app'"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "test-host",
            "source_paths": ["/data"],
            "output_file": "/tmp/backup.tar"
        });

        let args: SshBackupCreateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshBackupCreateArgs"));
        assert!(debug_str.contains("test-host"));
    }
}
