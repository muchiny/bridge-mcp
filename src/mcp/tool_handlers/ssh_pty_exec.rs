//! Handler for the `ssh_pty_exec` tool.
//!
//! Executes a command on a remote host with PTY (pseudo-terminal) allocation
//! using `script -q -c` for PTY emulation.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::pty::{PtyCommandBuilder, validate_dimensions, validate_pty_command};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshPtyExecArgs {
    /// Target host name from configuration.
    host: String,
    /// Command to execute with PTY allocation.
    command: String,
    /// Terminal rows (1-500).
    #[serde(default)]
    rows: Option<u32>,
    /// Terminal columns (1-500).
    #[serde(default)]
    cols: Option<u32>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshPtyExecArgs);

#[mcp_standard_tool(name = "ssh_pty_exec", group = "pty", annotation = "mutating")]
pub struct PtyExecTool;

impl StandardTool for PtyExecTool {
    type Args = SshPtyExecArgs;

    const NAME: &'static str = "ssh_pty_exec";

    const DESCRIPTION: &'static str = "Execute a command on a remote Linux host with \
        PTY (pseudo-terminal) allocation via script(1). Use this when a command requires \
        a terminal to run correctly (e.g. top, htop, vim, less). Optionally set terminal \
        dimensions via rows and cols (both must be provided together; range 1-500). \
        For multi-step interactive workflows with shared shell state (cd, env vars), \
        prefer ssh_session_create + ssh_session_exec instead. \
        Not available on Windows hosts.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute with PTY allocation via script(1) — must be non-empty"
                    },
                    "rows": {
                        "type": "integer",
                        "description": "Terminal rows (1-500); must be provided together with cols — ignored if cols is absent",
                        "minimum": 1,
                        "maximum": 500
                    },
                    "cols": {
                        "type": "integer",
                        "description": "Terminal columns (1-500); must be provided together with rows — ignored if rows is absent",
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
                "required": ["host", "command"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn validate(args: &SshPtyExecArgs, _host_config: &HostConfig) -> Result<()> {
        validate_pty_command(&args.command)?;
        if let (Some(r), Some(c)) = (args.rows, args.cols) {
            validate_dimensions(r, c)?;
        }
        Ok(())
    }

    fn build_command(args: &SshPtyExecArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PtyCommandBuilder::build_pty_exec_command(
            &args.command,
            args.rows,
            args.cols,
        ))
    }
}

/// Handler for the `ssh_pty_exec` tool.
pub type SshPtyExecHandler = StandardToolHandler<PtyExecTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPtyExecHandler::new();
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
        let handler = SshPtyExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "command": "top"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshPtyExecHandler::new();
        assert_eq!(handler.name(), "ssh_pty_exec");
        assert!(!handler.description().is_empty());
        assert!(handler.description().contains("PTY"));
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_pty_exec");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "command": "htop",
            "rows": 24,
            "cols": 80,
            "timeout_seconds": 30,
            "max_output": 10000,
            "save_output": "/tmp/pty.txt"
        });
        let args: SshPtyExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.command, "htop");
        assert_eq!(args.rows, Some(24));
        assert_eq!(args.cols, Some(80));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/pty.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "command": "top"
        });
        let args: SshPtyExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.command, "top");
        assert!(args.rows.is_none());
        assert!(args.cols.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPtyExecHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("rows"));
        assert!(props.contains_key("cols"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "command": "top"
        });
        let args: SshPtyExecArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPtyExecArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPtyExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "command": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_basic() {
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
        let args = SshPtyExecArgs {
            host: "s".to_string(),
            command: "top".to_string(),
            rows: None,
            cols: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = PtyExecTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("script -q -c"));
        assert!(cmd.contains("top"));
    }

    #[test]
    fn test_build_command_with_dimensions() {
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
        let args = SshPtyExecArgs {
            host: "s".to_string(),
            command: "htop".to_string(),
            rows: Some(24),
            cols: Some(80),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = PtyExecTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("stty rows 24 cols 80"));
        assert!(cmd.contains("script -q -c"));
    }
}
