//! Handler for the `ssh_template_diff` tool.
//!
//! Compares template content against the current file on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::templates::{TemplateCommandBuilder, validate_dest_path};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshTemplateDiffArgs {
    /// Target host name from configuration.
    host: String,
    /// The new template content to compare.
    content: String,
    /// Path to the current file on the remote host.
    current_path: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshTemplateDiffArgs);

#[mcp_standard_tool(
    name = "ssh_template_diff",
    group = "templates",
    annotation = "read_only"
)]
pub struct TemplateDiffTool;

impl StandardTool for TemplateDiffTool {
    type Args = SshTemplateDiffArgs;

    const NAME: &'static str = "ssh_template_diff";

    const DESCRIPTION: &'static str = "Compare proposed template content against an existing \
        configuration file on a Linux host, producing a unified diff. Use this before \
        ssh_template_apply to preview exactly what would change. Obtain template content \
        to compare with ssh_template_show, and validate the result afterward with \
        ssh_template_validate.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "content": {
                        "type": "string",
                        "description": "The new template content to compare against the current file"
                    },
                    "current_path": {
                        "type": "string",
                        "description": "Absolute path to the current configuration file on the remote host"
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
                "required": ["host", "content", "current_path"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn validate(args: &SshTemplateDiffArgs, _host_config: &HostConfig) -> Result<()> {
        validate_dest_path(&args.current_path)
    }

    fn build_command(args: &SshTemplateDiffArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(TemplateCommandBuilder::build_template_diff_command(
            &args.content,
            &args.current_path,
        ))
    }
}

/// Handler for the `ssh_template_diff` tool.
pub type SshTemplateDiffHandler = StandardToolHandler<TemplateDiffTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTemplateDiffHandler::new();
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
        let handler = SshTemplateDiffHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "content": "new content",
                    "current_path": "/etc/nginx/nginx.conf"
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
        let handler = SshTemplateDiffHandler::new();
        assert_eq!(handler.name(), "ssh_template_diff");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_template_diff");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("content")));
        assert!(required.contains(&json!("current_path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "content": "new content",
            "current_path": "/etc/nginx/nginx.conf",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/diff.txt"
        });
        let args: SshTemplateDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.content, "new content");
        assert_eq!(args.current_path, "/etc/nginx/nginx.conf");
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/diff.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "content": "test",
            "current_path": "/tmp/test.conf"
        });
        let args: SshTemplateDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.content, "test");
        assert_eq!(args.current_path, "/tmp/test.conf");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTemplateDiffHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "content": "test",
            "current_path": "/tmp/test"
        });
        let args: SshTemplateDiffArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshTemplateDiffArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTemplateDiffHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "content": 456, "current_path": 789})),
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
    fn test_build_command() {
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
        let args = SshTemplateDiffArgs {
            host: "s".to_string(),
            content: "new content".to_string(),
            current_path: "/etc/nginx/nginx.conf".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TemplateDiffTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("diff"));
        assert!(cmd.contains("/etc/nginx/nginx.conf"));
    }

    #[test]
    fn test_build_command_with_special_content() {
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
        let args = SshTemplateDiffArgs {
            host: "s".to_string(),
            content: "content with 'quotes'".to_string(),
            current_path: "/tmp/test.conf".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TemplateDiffTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("diff"));
    }
}
