//! SSH Git Clone Tool Handler
//!
//! Clones a Git repository on a remote host via `git clone`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::git::GitCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshGitCloneArgs {
    host: String,
    url: String,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    depth: Option<u32>,
    #[serde(default)]
    single_branch: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshGitCloneArgs);

#[mcp_standard_tool(name = "ssh_git_clone", group = "git", annotation = "mutating")]
pub struct GitCloneTool;

impl StandardTool for GitCloneTool {
    type Args = SshGitCloneArgs;

    const NAME: &'static str = "ssh_git_clone";

    const DESCRIPTION: &'static str = "Clone a Git repository on a remote host. Supports shallow clones (--depth), branch \
        selection (--branch), and single-branch mode. The URL can be HTTPS or SSH.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "url": {
                "type": "string",
                "description": "Repository URL to clone (HTTPS or SSH)"
            },
            "destination": {
                "type": "string",
                "description": "Target directory path on the remote host (default: derived from URL)"
            },
            "branch": {
                "type": "string",
                "description": "Branch to clone (maps to --branch, default: default branch)"
            },
            "depth": {
                "type": "integer",
                "description": "Create a shallow clone with N commits (maps to --depth)",
                "minimum": 1
            },
            "single_branch": {
                "type": "boolean",
                "description": "Clone only the specified branch (default: false)"
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
        "required": ["host", "url"]
    }"#;

    fn build_command(args: &SshGitCloneArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(GitCommandBuilder::build_clone_command(
            &args.url,
            args.destination.as_deref(),
            args.branch.as_deref(),
            args.depth,
            args.single_branch.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_git_clone` tool.
pub type SshGitCloneHandler = StandardToolHandler<GitCloneTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshGitCloneHandler::new();
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
        let handler = SshGitCloneHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "url": "https://github.com/user/repo.git"})),
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
        let handler = SshGitCloneHandler::new();
        assert_eq!(handler.name(), "ssh_git_clone");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_git_clone");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("url")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "url": "https://github.com/user/repo.git",
            "destination": "/opt/myrepo",
            "branch": "develop",
            "depth": 1,
            "single_branch": true
        });
        let args: SshGitCloneArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.url, "https://github.com/user/repo.git");
        assert_eq!(args.destination, Some("/opt/myrepo".to_string()));
        assert_eq!(args.depth, Some(1));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "url": "https://github.com/user/repo.git"});
        let args: SshGitCloneArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.destination.is_none());
        assert!(args.depth.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshGitCloneHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("destination"));
        assert!(properties.contains_key("branch"));
        assert!(properties.contains_key("depth"));
        assert!(properties.contains_key("single_branch"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "url": "https://github.com/user/repo.git"});
        let args: SshGitCloneArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshGitCloneArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshGitCloneHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "url": "https://github.com/user/repo.git"})),
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
        let args = SshGitCloneArgs {
            host: "s".to_string(),
            url: "https://github.com/user/repo.git".to_string(),
            destination: None,
            branch: None,
            depth: None,
            single_branch: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = GitCloneTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("git clone"));
        assert!(cmd.contains("https://github.com/user/repo.git"));
    }

    #[test]
    fn test_build_command_with_branch_depth() {
        let args = SshGitCloneArgs {
            host: "s".to_string(),
            url: "git@github.com:user/repo.git".to_string(),
            destination: Some("/opt/repo".to_string()),
            branch: Some("develop".to_string()),
            depth: Some(1),
            single_branch: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = GitCloneTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("git clone"));
        assert!(cmd.contains("develop"));
        assert!(cmd.contains("--depth"));
    }
}
