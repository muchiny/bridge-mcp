//! SSH File Diff Tool Handler
//!
//! Compares two files on a remote host using unified diff format.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::file_advanced::FileAdvancedCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshFileDiffArgs {
    host: String,
    file1: String,
    file2: String,
    #[serde(default)]
    context_lines: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshFileDiffArgs);

#[mcp_standard_tool(name = "ssh_file_diff", group = "file_ops", annotation = "read_only")]
pub struct FileDiffTool;

impl StandardTool for FileDiffTool {
    type Args = SshFileDiffArgs;

    const NAME: &'static str = "ssh_file_diff";

    const DESCRIPTION: &'static str = "Compare two files on a remote host using unified diff \
        format. Returns the differences between file1 and file2. Both files must exist on the \
        same remote host; for cross-host comparison, read each file separately with ssh_file_read \
        and diff locally.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "file1": {
                "type": "string",
                "description": "Absolute path to the first file"
            },
            "file2": {
                "type": "string",
                "description": "Absolute path to the second file"
            },
            "context_lines": {
                "type": "integer",
                "description": "Number of context lines in diff output (default: 3)",
                "minimum": 0,
                "maximum": 100
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: 60)",
                "minimum": 1,
                "maximum": 300
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from config)",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to local file"
            }
        },
        "required": ["host", "file1", "file2"]
    }"#;

    fn scoped_paths(args: &SshFileDiffArgs) -> Vec<&str> {
        vec![&args.file1, &args.file2]
    }

    fn build_command(args: &SshFileDiffArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(FileAdvancedCommandBuilder::build_diff_command(
            &args.file1,
            &args.file2,
            args.context_lines.unwrap_or(3),
        ))
    }
}

pub type SshFileDiffHandler = StandardToolHandler<FileDiffTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

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

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFileDiffHandler::new();
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
        let handler = SshFileDiffHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "file1": "/a", "file2": "/b"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshFileDiffHandler::new();
        assert_eq!(handler.name(), "ssh_file_diff");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("file1")));
        assert!(required.contains(&json!("file2")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "file1": "/etc/nginx/a.conf",
            "file2": "/etc/nginx/b.conf",
            "context_lines": 5,
            "timeout_seconds": 30
        });
        let args: SshFileDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.file1, "/etc/nginx/a.conf");
        assert_eq!(args.file2, "/etc/nginx/b.conf");
        assert_eq!(args.context_lines, Some(5));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1", "file1": "/a", "file2": "/b"});
        let args: SshFileDiffArgs = serde_json::from_value(json).unwrap();
        assert!(args.context_lines.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshFileDiffArgs {
            host: "server1".to_string(),
            file1: "/etc/nginx/a.conf".to_string(),
            file2: "/etc/nginx/b.conf".to_string(),
            context_lines: Some(5),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileDiffTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("diff -u"));
        assert!(cmd.contains("-U 5"));
        assert!(cmd.contains("/etc/nginx/a.conf"));
        assert!(cmd.contains("/etc/nginx/b.conf"));
    }
}
