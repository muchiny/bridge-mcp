//! SSH File Chown Tool Handler
//!
//! Changes file ownership on a remote host using chown.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::file_ops::FileOpsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshFileChownArgs {
    host: String,
    path: String,
    owner: String,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    recursive: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshFileChownArgs);

#[mcp_standard_tool(name = "ssh_file_chown", group = "file_ops", annotation = "mutating")]
pub struct FileChownTool;

impl StandardTool for FileChownTool {
    type Args = SshFileChownArgs;

    const NAME: &'static str = "ssh_file_chown";

    const DESCRIPTION: &'static str = "Change file ownership on a remote host using chown. Set \
        owner and optionally group. Use recursive=true for directories.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "path": {
                "type": "string",
                "description": "Absolute path of the file or directory on the remote host"
            },
            "owner": {
                "type": "string",
                "description": "New owner username or UID"
            },
            "group": {
                "type": "string",
                "description": "New group name or GID (optional, only owner is changed if omitted)"
            },
            "recursive": {
                "type": "boolean",
                "description": "Apply ownership recursively to directory contents (default: false)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "path", "owner"]
    }"#;

    fn scoped_paths(args: &SshFileChownArgs) -> Vec<&str> {
        vec![&args.path]
    }

    fn build_command(args: &SshFileChownArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(FileOpsCommandBuilder::build_chown_command(
            &args.path,
            &args.owner,
            args.group.as_deref(),
            args.recursive.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_file_chown` tool.
pub type SshFileChownHandler = StandardToolHandler<FileChownTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFileChownHandler::new();
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
        let handler = SshFileChownHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/tmp/test", "owner": "root"})),
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
        let handler = SshFileChownHandler::new();
        assert_eq!(handler.name(), "ssh_file_chown");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_file_chown");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
        assert!(required.contains(&json!("owner")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/var/www",
            "owner": "www-data",
            "group": "www-data",
            "recursive": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/output.txt"
        });
        let args: SshFileChownArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/var/www");
        assert_eq!(args.owner, "www-data");
        assert_eq!(args.group, Some("www-data".to_string()));
        assert_eq!(args.recursive, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/tmp/test", "owner": "root"});
        let args: SshFileChownArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/tmp/test");
        assert_eq!(args.owner, "root");
        assert!(args.group.is_none());
        assert!(args.recursive.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFileChownHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("group"));
        assert!(properties.contains_key("recursive"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/tmp/test", "owner": "root"});
        let args: SshFileChownArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFileChownArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFileChownHandler::new();
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
    fn test_build_command_owner_only() {
        let args = SshFileChownArgs {
            host: "server1".to_string(),
            path: "/tmp/file".to_string(),
            owner: "admin".to_string(),
            group: None,
            recursive: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileChownTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("chown"));
        assert!(cmd.contains("admin"));
        assert!(!cmd.contains(':'));
    }

    #[test]
    fn test_build_command_owner_and_group() {
        let args = SshFileChownArgs {
            host: "server1".to_string(),
            path: "/tmp/file".to_string(),
            owner: "root".to_string(),
            group: Some("www-data".to_string()),
            recursive: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileChownTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("chown"));
        assert!(cmd.contains("root:www-data"));
    }

    #[test]
    fn test_build_command_recursive() {
        let args = SshFileChownArgs {
            host: "server1".to_string(),
            path: "/var/www".to_string(),
            owner: "www-data".to_string(),
            group: Some("www-data".to_string()),
            recursive: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileChownTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-R"));
    }
}
