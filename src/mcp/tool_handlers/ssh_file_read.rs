//! SSH File Read Tool Handler
//!
//! Reads the contents of a file on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::file_ops::FileOpsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshFileReadArgs {
    host: String,
    path: String,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshFileReadArgs);

#[mcp_standard_tool(name = "ssh_file_read", group = "file_ops", annotation = "read_only")]
pub struct FileReadTool;

impl StandardTool for FileReadTool {
    type Args = SshFileReadArgs;

    const NAME: &'static str = "ssh_file_read";

    const DESCRIPTION: &'static str = "Read the contents of a file on a remote host. Returns \
        file content as text. Supports optional line offset and limit for reading specific \
        portions of large files. For binary files, use ssh_download instead. To read the last N \
        lines of a log file efficiently, prefer ssh_tail. To check file metadata (permissions, \
        size, mtime) without reading content, use ssh_file_stat.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "path": {
                "type": "string",
                "description": "Absolute path of the file to read on the remote host"
            },
            "offset": {
                "type": "integer",
                "description": "Starting line number (1-based) for partial reads",
                "minimum": 1
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of lines to read from the offset",
                "minimum": 1
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
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "path"]
    }"#;

    fn scoped_paths(args: &SshFileReadArgs) -> Vec<&str> {
        vec![&args.path]
    }

    fn build_command(args: &SshFileReadArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(FileOpsCommandBuilder::build_read_command(
            &args.path,
            args.offset,
            args.limit,
        ))
    }
}

/// Handler for the `ssh_file_read` tool.
pub type SshFileReadHandler = StandardToolHandler<FileReadTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFileReadHandler::new();
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
        let handler = SshFileReadHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/etc/hosts"})),
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
        let handler = SshFileReadHandler::new();
        assert_eq!(handler.name(), "ssh_file_read");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_file_read");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/etc/hosts",
            "offset": 10,
            "limit": 50,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/output.txt"
        });
        let args: SshFileReadArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/etc/hosts");
        assert_eq!(args.offset, Some(10));
        assert_eq!(args.limit, Some(50));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/etc/hosts"});
        let args: SshFileReadArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/etc/hosts");
        assert!(args.offset.is_none());
        assert!(args.limit.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFileReadHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("offset"));
        assert!(properties.contains_key("limit"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/etc/hosts"});
        let args: SshFileReadArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFileReadArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFileReadHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
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
    fn test_build_command_simple() {
        let args = SshFileReadArgs {
            host: "server1".to_string(),
            path: "/etc/hosts".to_string(),
            offset: None,
            limit: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileReadTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("cat"));
        assert!(cmd.contains("/etc/hosts"));
    }

    #[test]
    fn test_build_command_with_offset_limit() {
        let args = SshFileReadArgs {
            host: "server1".to_string(),
            path: "/var/log/syslog".to_string(),
            offset: Some(10),
            limit: Some(20),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileReadTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("sed"));
    }
}
