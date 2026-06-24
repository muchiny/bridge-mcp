//! SSH File Patch Tool Handler
//!
//! Applies a unified diff patch to a file on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::file_advanced::FileAdvancedCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshFilePatchArgs {
    host: String,
    target_file: String,
    patch_content: String,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshFilePatchArgs);

#[mcp_standard_tool(
    name = "ssh_file_patch",
    group = "file_ops",
    annotation = "destructive"
)]
pub struct FilePatchTool;

impl StandardTool for FilePatchTool {
    type Args = SshFilePatchArgs;

    const NAME: &'static str = "ssh_file_patch";

    const DESCRIPTION: &'static str = "Apply a unified diff patch to a file on a remote host. \
        The patch is applied with patch -p0, meaning filenames in the patch must match the \
        target_file path exactly with no leading path components to strip. For patches produced \
        by git diff (which include a/ and b/ prefixes), remove those prefixes from the patch \
        content before passing it, or specify just the target filename in target_file matching \
        the stripped path. Use dry_run=true to preview changes without applying.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "target_file": {
                "type": "string",
                "description": "Absolute path to the file to patch"
            },
            "patch_content": {
                "type": "string",
                "description": "Unified diff patch content to apply"
            },
            "dry_run": {
                "type": "boolean",
                "description": "Preview changes without applying (default: false)"
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
        "required": ["host", "target_file", "patch_content"]
    }"#;

    fn scoped_paths(args: &SshFilePatchArgs) -> Vec<&str> {
        vec![&args.target_file]
    }

    fn build_command(args: &SshFilePatchArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(FileAdvancedCommandBuilder::build_patch_command(
            &args.target_file,
            &args.patch_content,
            args.dry_run.unwrap_or(false),
        ))
    }

    /// Confirm destructive operation via `elicitation/create` before
    /// running the underlying command. Falls back to a no-op when the
    /// client does not advertise the elicitation capability — the
    /// global `security.require_elicitation_on_destructive` gate still
    /// applies in that case.
    async fn pre_execute(args: &Self::Args, ctx: &ToolContext) -> Result<Option<ToolCallResult>> {
        let summary = format!(
            "Apply patch to file `{}` on host `{}`",
            args.target_file, args.host,
        );
        match ctx.elicit_confirm(Self::NAME, &summary).await? {
            Some(false) => Ok(Some(ToolCallResult::error(
                "User declined destructive operation".to_string(),
            ))),
            _ => Ok(None),
        }
    }
}

pub type SshFilePatchHandler = StandardToolHandler<FilePatchTool>;

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
        let handler = SshFilePatchHandler::new();
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
        let handler = SshFilePatchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "target_file": "/etc/config",
                    "patch_content": "--- a\n+++ b\n"
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshFilePatchHandler::new();
        assert_eq!(handler.name(), "ssh_file_patch");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("target_file")));
        assert!(required.contains(&json!("patch_content")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "target_file": "/etc/config",
            "patch_content": "--- a\n+++ b\n",
            "dry_run": true,
            "timeout_seconds": 30
        });
        let args: SshFilePatchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target_file, "/etc/config");
        assert_eq!(args.dry_run, Some(true));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({
            "host": "server1",
            "target_file": "/etc/config",
            "patch_content": "--- a\n+++ b\n"
        });
        let args: SshFilePatchArgs = serde_json::from_value(json).unwrap();
        assert!(args.dry_run.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshFilePatchArgs {
            host: "server1".to_string(),
            target_file: "/etc/config".to_string(),
            patch_content: "--- a\n+++ b\n".to_string(),
            dry_run: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FilePatchTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("patch"));
        assert!(cmd.contains("--dry-run"));
    }
}
