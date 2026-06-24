//! SSH Git Branch Tool Handler
//!
//! Manages branches in a Git repository on a remote host
//! via `git -C {path} branch`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::git::GitCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshGitBranchArgs {
    host: String,
    path: String,
    action: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    remote: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshGitBranchArgs);

#[mcp_standard_tool(name = "ssh_git_branch", group = "git", annotation = "mutating")]
pub struct GitBranchTool;

impl StandardTool for GitBranchTool {
    type Args = SshGitBranchArgs;

    const NAME: &'static str = "ssh_git_branch";

    const DESCRIPTION: &'static str = "Manage branches in a Git repository on a remote host. Actions: list (local branches, \
        or remote-tracking with remote=true), create (new branch from current HEAD), delete \
        (remove branch using -d, which refuses to delete unmerged branches — no force-delete is \
        available; use ssh_exec with 'git branch -D' if force is needed). Use ssh_git_checkout \
        to switch to a branch.";

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
            "action": {
                "type": "string",
                "description": "Branch action to perform",
                "enum": ["list", "create", "delete"]
            },
            "name": {
                "type": "string",
                "description": "Branch name (required for create and delete)"
            },
            "remote": {
                "type": "boolean",
                "description": "Show remote-tracking branches only (git branch -r) instead of local branches when action=list (default: false). To list both local and remote, use ssh_exec with 'git branch -a'."
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
        "required": ["host", "path", "action"]
    }"#;

    fn validate(args: &SshGitBranchArgs, _host_config: &HostConfig) -> Result<()> {
        GitCommandBuilder::validate_branch_action(&args.action)
    }

    fn build_command(args: &SshGitBranchArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(GitCommandBuilder::build_branch_command(
            &args.path,
            &args.action,
            args.name.as_deref(),
            args.remote.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_git_branch` tool.
pub type SshGitBranchHandler = StandardToolHandler<GitBranchTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshGitBranchHandler::new();
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
        let handler = SshGitBranchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/opt/repo", "action": "list"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_action() {
        let handler = SshGitBranchHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "path": "/opt/repo", "action": "rename"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("rename"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshGitBranchHandler::new();
        assert_eq!(handler.name(), "ssh_git_branch");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_git_branch");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
        assert!(required.contains(&json!("action")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/opt/repo",
            "action": "create",
            "name": "feature-x",
            "remote": false
        });
        let args: SshGitBranchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.action, "create");
        assert_eq!(args.name, Some("feature-x".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/opt/repo", "action": "list"});
        let args: SshGitBranchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.action, "list");
        assert!(args.name.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshGitBranchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1", "path": "/opt/repo"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshGitBranchHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("name"));
        assert!(properties.contains_key("remote"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/opt/repo", "action": "list"});
        let args: SshGitBranchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshGitBranchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshGitBranchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "path": "/opt/repo", "action": "list"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
