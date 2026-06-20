//! Handler for the `ssh_template_apply` tool.
//!
//! Applies a configuration template to a remote host by writing content
//! to a destination file, optionally creating a backup first.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::templates::{TemplateCommandBuilder, validate_dest_path};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshTemplateApplyArgs {
    /// Target host name from configuration.
    host: String,
    /// The template content to write.
    content: String,
    /// Destination file path on the remote host.
    dest: String,
    /// Whether to create a .bak backup before overwriting.
    #[serde(default)]
    backup: Option<bool>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshTemplateApplyArgs);

#[mcp_standard_tool(
    name = "ssh_template_apply",
    group = "templates",
    annotation = "destructive"
)]
pub struct TemplateApplyTool;

impl StandardTool for TemplateApplyTool {
    type Args = SshTemplateApplyArgs;

    const NAME: &'static str = "ssh_template_apply";

    const DESCRIPTION: &'static str = "Write arbitrary configuration content to a destination \
        file on a Linux host (destructive — overwrites the file). Use backup=true to create \
        a .bak copy first. Typical workflow: ssh_template_list → ssh_template_show → \
        ssh_template_diff (preview) → ssh_template_apply → ssh_template_validate. \
        For envsubst-style variable substitution on an existing remote template file use \
        ssh_file_template instead.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "content": {
                        "type": "string",
                        "description": "The template content to write to the destination file"
                    },
                    "dest": {
                        "type": "string",
                        "description": "Absolute destination file path on the remote host"
                    },
                    "backup": {
                        "type": "boolean",
                        "description": "Create a .bak backup before overwriting (recommended)",
                        "default": false
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host", "content", "dest"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn validate(args: &SshTemplateApplyArgs, _host_config: &HostConfig) -> Result<()> {
        validate_dest_path(&args.dest)
    }

    fn build_command(args: &SshTemplateApplyArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(TemplateCommandBuilder::build_template_apply_command(
            &args.content,
            &args.dest,
            args.backup.unwrap_or(false),
        ))
    }

    /// Confirm destructive operation via `elicitation/create` before
    /// running the underlying command. Falls back to a no-op when the
    /// client does not advertise the elicitation capability — the
    /// global `security.require_elicitation_on_destructive` gate still
    /// applies in that case.
    async fn pre_execute(args: &Self::Args, ctx: &ToolContext) -> Result<Option<ToolCallResult>> {
        let summary = format!(
            "Apply template content to `{}` on host `{}`",
            args.dest, args.host,
        );
        match ctx.elicit_confirm(Self::NAME, &summary).await? {
            Some(false) => Ok(Some(ToolCallResult::error(
                "User declined destructive operation".to_string(),
            ))),
            _ => Ok(None),
        }
    }
}

/// Handler for the `ssh_template_apply` tool.
pub type SshTemplateApplyHandler = StandardToolHandler<TemplateApplyTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTemplateApplyHandler::new();
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
        let handler = SshTemplateApplyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "content": "test",
                    "dest": "/tmp/test.conf"
                })),
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
        let handler = SshTemplateApplyHandler::new();
        assert_eq!(handler.name(), "ssh_template_apply");
        assert!(!handler.description().is_empty());
        assert!(handler.description().contains("destructive"));
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_template_apply");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("content")));
        assert!(required.contains(&json!("dest")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "content": "server { listen 80; }",
            "dest": "/etc/nginx/conf.d/default.conf",
            "backup": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/apply.txt"
        });
        let args: SshTemplateApplyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.content, "server { listen 80; }");
        assert_eq!(args.dest, "/etc/nginx/conf.d/default.conf");
        assert_eq!(args.backup, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/apply.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "content": "test content",
            "dest": "/tmp/test.conf"
        });
        let args: SshTemplateApplyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.content, "test content");
        assert_eq!(args.dest, "/tmp/test.conf");
        assert!(args.backup.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTemplateApplyHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("backup"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "content": "test",
            "dest": "/tmp/test"
        });
        let args: SshTemplateApplyArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshTemplateApplyArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTemplateApplyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "content": 456, "dest": 789})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_no_backup() {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let host_config = HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: AuthConfig::Agent,
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
        };
        let args = SshTemplateApplyArgs {
            host: "s".to_string(),
            content: "server {}".to_string(),
            dest: "/etc/nginx/nginx.conf".to_string(),
            backup: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TemplateApplyTool::build_command(&args, &host_config).unwrap();
        // Heredoc terminator is randomized per call (Vuln 4 fix); extract it dynamically.
        let start = cmd.find("<< '").expect("heredoc opening present") + 4;
        let end = cmd[start..].find('\'').expect("terminator close quote") + start;
        let terminator = &cmd[start..end];
        assert!(terminator.starts_with("MCP_EOF_"));
        assert!(cmd.contains(terminator));
        assert!(!cmd.contains(".bak"));
    }

    #[test]
    fn test_build_command_with_backup() {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let host_config = HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: AuthConfig::Agent,
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
        };
        let args = SshTemplateApplyArgs {
            host: "s".to_string(),
            content: "content".to_string(),
            dest: "/tmp/test.conf".to_string(),
            backup: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TemplateApplyTool::build_command(&args, &host_config).unwrap();
        // Heredoc terminator is randomized per call (Vuln 4 fix); extract it dynamically.
        let start = cmd.find("<< '").expect("heredoc opening present") + 4;
        let end = cmd[start..].find('\'').expect("terminator close quote") + start;
        let terminator = &cmd[start..end];
        assert!(terminator.starts_with("MCP_EOF_"));
        assert!(cmd.contains(".bak"));
        assert!(cmd.contains(terminator));
    }
}
