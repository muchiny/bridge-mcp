//! SSH File Stat Tool Handler
//!
//! Gets detailed file information on a remote host using stat.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::file_ops::FileOpsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshFileStatArgs {
    host: String,
    path: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshFileStatArgs);

#[mcp_standard_tool(name = "ssh_file_stat", group = "file_ops", annotation = "read_only")]
pub struct FileStatTool;

impl StandardTool for FileStatTool {
    type Args = SshFileStatArgs;

    const NAME: &'static str = "ssh_file_stat";

    const DESCRIPTION: &'static str = "Get detailed file information on a remote host using stat. \
        Returns permissions, owner, group, size, modification time, and file type as text. \
        Output is human-readable stat format; to extract a specific field programmatically, \
        pipe the result through a follow-up ssh_exec (e.g., stat -c '%a' for octal permissions, \
        stat -c '%s' for size in bytes, stat -c '%Y' for mtime as epoch). Use before \
        ssh_file_chmod or ssh_file_chown to verify the current state.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "path": {
                "type": "string",
                "description": "Absolute path of the file to inspect on the remote host"
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

    fn scoped_paths(args: &SshFileStatArgs) -> Vec<&str> {
        vec![&args.path]
    }

    fn build_command(args: &SshFileStatArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(FileOpsCommandBuilder::build_stat_command(&args.path))
    }
}

/// Handler for the `ssh_file_stat` tool.
pub type SshFileStatHandler = StandardToolHandler<FileStatTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFileStatHandler::new();
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
        let handler = SshFileStatHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/etc/passwd"})),
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
        let handler = SshFileStatHandler::new();
        assert_eq!(handler.name(), "ssh_file_stat");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_file_stat");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/etc/passwd",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/output.txt"
        });
        let args: SshFileStatArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/etc/passwd");
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/etc/passwd"});
        let args: SshFileStatArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/etc/passwd");
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFileStatHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/etc/passwd"});
        let args: SshFileStatArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFileStatArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFileStatHandler::new();
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
    fn test_build_command_basic() {
        let args = SshFileStatArgs {
            host: "server1".to_string(),
            path: "/etc/passwd".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileStatTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("stat"));
        assert!(cmd.contains("/etc/passwd"));
    }

    #[test]
    fn test_build_command_different_path() {
        let args = SshFileStatArgs {
            host: "server1".to_string(),
            path: "/var/log/syslog".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileStatTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("stat"));
        assert!(cmd.contains("/var/log/syslog"));
    }
}
