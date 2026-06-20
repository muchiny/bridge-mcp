//! SSH Git Log Tool Handler
//!
//! Shows commit history of a Git repository on a remote host
//! via `git -C {path} log`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::git::GitCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshGitLogArgs {
    host: String,
    path: String,
    #[serde(default)]
    max_count: Option<u32>,
    #[serde(default)]
    oneline: Option<bool>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default, rename = "format")]
    log_format: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshGitLogArgs);

#[mcp_standard_tool(name = "ssh_git_log", group = "git", annotation = "read_only")]
pub struct GitLogTool;

impl StandardTool for GitLogTool {
    type Args = SshGitLogArgs;

    const NAME: &'static str = "ssh_git_log";

    const DESCRIPTION: &'static str = "Show commit history of a Git repository on a remote host. Outputs plain text — \
        use max_count to cap result size and oneline or format for compact per-commit lines. \
        Supports filtering by branch, author, and date (--since). For reading file content or \
        working-tree state use ssh_git_status or ssh_git_diff instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "path": {
                "type": "string",
                "description": "Absolute path to the Git repository on the remote host"
            },
            "max_count": {
                "type": "integer",
                "description": "Limit number of commits to show (maps to --max-count)",
                "minimum": 1
            },
            "oneline": {
                "type": "boolean",
                "description": "Show each commit on a single line (default: false)"
            },
            "branch": {
                "type": "string",
                "description": "Branch name to show log for (default: current branch)"
            },
            "author": {
                "type": "string",
                "description": "Filter commits by author (maps to --author)"
            },
            "since": {
                "type": "string",
                "description": "Show commits after date (maps to --since, e.g. '2024-01-01' or '1 week ago')"
            },
            "format": {
                "type": "string",
                "description": "Pretty-print format string passed to --format (equivalent to --pretty=tformat:). Each placeholder is expanded per commit, e.g. '%H %s' for hash + subject, '%an %ae' for author name/email, '%ad' for author date. See git-log(1) PRETTY FORMATS for all placeholders. Mutually exclusive with oneline."
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

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshGitLogArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(GitCommandBuilder::build_log_command(
            &args.path,
            args.max_count,
            args.oneline.unwrap_or(false),
            args.branch.as_deref(),
            args.author.as_deref(),
            args.since.as_deref(),
            args.log_format.as_deref(),
        ))
    }
}

/// Handler for the `ssh_git_log` tool.
pub type SshGitLogHandler = StandardToolHandler<GitLogTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshGitLogHandler::new();
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
        let handler = SshGitLogHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/opt/repo"})),
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
        let handler = SshGitLogHandler::new();
        assert_eq!(handler.name(), "ssh_git_log");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_git_log");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/opt/repo",
            "max_count": 10,
            "oneline": true,
            "branch": "main",
            "author": "alice",
            "since": "1 week ago",
            "format": "%H %s"
        });
        let args: SshGitLogArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/opt/repo");
        assert_eq!(args.max_count, Some(10));
        assert_eq!(args.oneline, Some(true));
        assert_eq!(args.branch, Some("main".to_string()));
        assert_eq!(args.log_format, Some("%H %s".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/opt/repo"});
        let args: SshGitLogArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.max_count.is_none());
        assert!(args.branch.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshGitLogHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("max_count"));
        assert!(properties.contains_key("oneline"));
        assert!(properties.contains_key("branch"));
        assert!(properties.contains_key("author"));
        assert!(properties.contains_key("since"));
        assert!(properties.contains_key("format"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/opt/repo"});
        let args: SshGitLogArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshGitLogArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshGitLogHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "path": "/opt/repo"})), &ctx)
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
        let args = SshGitLogArgs {
            host: "s".to_string(),
            path: "/opt/repo".to_string(),
            max_count: None,
            oneline: None,
            branch: None,
            author: None,
            since: None,
            log_format: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = GitLogTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("git"));
        assert!(cmd.contains("log"));
        assert!(cmd.contains("/opt/repo"));
    }

    #[test]
    fn test_build_command_with_count_format() {
        let args = SshGitLogArgs {
            host: "s".to_string(),
            path: "/opt/repo".to_string(),
            max_count: Some(20),
            oneline: Some(true),
            branch: Some("main".to_string()),
            author: Some("dev@example.com".to_string()),
            since: Some("2024-01-01".to_string()),
            log_format: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = GitLogTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("log"));
        assert!(cmd.contains("20"));
        assert!(cmd.contains("main"));
    }
}
