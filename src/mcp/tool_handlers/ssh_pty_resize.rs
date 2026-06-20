//! Handler for the `ssh_pty_resize` tool.
//!
//! Resizes the terminal on a remote host by setting rows and columns
//! via `stty`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::pty::{PtyCommandBuilder, validate_dimensions};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshPtyResizeArgs {
    /// Target host name from configuration.
    host: String,
    /// Number of terminal rows (1-500).
    rows: u32,
    /// Number of terminal columns (1-500).
    cols: u32,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshPtyResizeArgs);

#[mcp_standard_tool(name = "ssh_pty_resize", group = "pty", annotation = "mutating")]
pub struct PtyResizeTool;

impl StandardTool for PtyResizeTool {
    type Args = SshPtyResizeArgs;

    const NAME: &'static str = "ssh_pty_resize";

    const DESCRIPTION: &'static str = "Resize the terminal on a remote host by setting \
        the number of rows and columns via stty. Use this after ssh_pty_exec to adjust \
        terminal dimensions for interactive commands.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "rows": {
                        "type": "integer",
                        "description": "Number of terminal rows (1-500)",
                        "minimum": 1,
                        "maximum": 500
                    },
                    "cols": {
                        "type": "integer",
                        "description": "Number of terminal columns (1-500)",
                        "minimum": 1,
                        "maximum": 500
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
                "required": ["host", "rows", "cols"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn validate(args: &SshPtyResizeArgs, _host_config: &HostConfig) -> Result<()> {
        validate_dimensions(args.rows, args.cols)
    }

    fn build_command(args: &SshPtyResizeArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PtyCommandBuilder::build_pty_resize_command(
            args.rows, args.cols,
        ))
    }
}

/// Handler for the `ssh_pty_resize` tool.
pub type SshPtyResizeHandler = StandardToolHandler<PtyResizeTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPtyResizeHandler::new();
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
        let handler = SshPtyResizeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "rows": 24, "cols": 80})),
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
        let handler = SshPtyResizeHandler::new();
        assert_eq!(handler.name(), "ssh_pty_resize");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_pty_resize");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("rows")));
        assert!(required.contains(&json!("cols")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "rows": 24,
            "cols": 80,
            "timeout_seconds": 10,
            "max_output": 5000,
            "save_output": "/tmp/resize.txt"
        });
        let args: SshPtyResizeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.rows, 24);
        assert_eq!(args.cols, 80);
        assert_eq!(args.timeout_seconds, Some(10));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/resize.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "rows": 50,
            "cols": 120
        });
        let args: SshPtyResizeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.rows, 50);
        assert_eq!(args.cols, 120);
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPtyResizeHandler::new();
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
            "rows": 24,
            "cols": 80
        });
        let args: SshPtyResizeArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPtyResizeArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPtyResizeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "rows": "abc", "cols": "def"})),
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
        let args = SshPtyResizeArgs {
            host: "s".to_string(),
            rows: 24,
            cols: 80,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = PtyResizeTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "stty rows 24 cols 80");
    }

    #[test]
    fn test_build_command_large_dimensions() {
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
        let args = SshPtyResizeArgs {
            host: "s".to_string(),
            rows: 500,
            cols: 500,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = PtyResizeTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "stty rows 500 cols 500");
    }
}
