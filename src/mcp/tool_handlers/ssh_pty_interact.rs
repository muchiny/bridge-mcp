//! Handler for the `ssh_pty_interact` tool.
//!
//! Sends input to a PTY session on a remote host. Since `StandardTool` cannot
//! maintain persistent sessions, this is implemented as a simple command
//! that pipes input via echo.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::shell;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshPtyInteractArgs {
    /// Target host name from configuration.
    host: String,
    /// Session identifier (for future session management).
    #[allow(dead_code)]
    session_id: String,
    /// Input to send to the session.
    input: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshPtyInteractArgs);

#[mcp_standard_tool(name = "ssh_pty_interact", group = "pty", annotation = "mutating")]
pub struct PtyInteractTool;

impl StandardTool for PtyInteractTool {
    type Args = SshPtyInteractArgs;

    const NAME: &'static str = "ssh_pty_interact";

    const DESCRIPTION: &'static str = "Send a line of text to a remote Linux host's \
        shell by running echo <input>. This is a limited helper: it does NOT maintain \
        a persistent PTY session — each call is a standalone echo command and the \
        session_id field is accepted but currently ignored (no session state is stored). \
        For true interactive PTY execution use ssh_pty_exec. For multi-step shell \
        workflows with shared state use ssh_session_create + ssh_session_exec. \
        Not available on Windows hosts.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Session identifier (accepted for API compatibility but currently unused — no session state is maintained between calls)"
                    },
                    "input": {
                        "type": "string",
                        "description": "Input text to send to the session"
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
                "required": ["host", "session_id", "input"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshPtyInteractArgs, _host_config: &HostConfig) -> Result<String> {
        let escaped_input = shell::escape(&args.input, crate::config::ShellType::Posix);
        Ok(format!("echo {escaped_input}"))
    }
}

/// Handler for the `ssh_pty_interact` tool.
pub type SshPtyInteractHandler = StandardToolHandler<PtyInteractTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPtyInteractHandler::new();
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
        let handler = SshPtyInteractHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "session_id": "sess-123",
                    "input": "ls"
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
        let handler = SshPtyInteractHandler::new();
        assert_eq!(handler.name(), "ssh_pty_interact");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_pty_interact");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("session_id")));
        assert!(required.contains(&json!("input")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "session_id": "sess-abc-123",
            "input": "ls -la",
            "timeout_seconds": 10,
            "max_output": 5000,
            "save_output": "/tmp/interact.txt"
        });
        let args: SshPtyInteractArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.session_id, "sess-abc-123");
        assert_eq!(args.input, "ls -la");
        assert_eq!(args.timeout_seconds, Some(10));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/interact.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "session_id": "sess-1",
            "input": "pwd"
        });
        let args: SshPtyInteractArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.session_id, "sess-1");
        assert_eq!(args.input, "pwd");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPtyInteractHandler::new();
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
            "session_id": "sess-1",
            "input": "test"
        });
        let args: SshPtyInteractArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPtyInteractArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPtyInteractHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "session_id": 456, "input": 789})),
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
        let args = SshPtyInteractArgs {
            host: "s".to_string(),
            session_id: "sess-1".to_string(),
            input: "ls -la".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = PtyInteractTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("echo"));
        assert!(cmd.contains("ls -la"));
    }

    #[test]
    fn test_build_command_injection_safe() {
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
        let args = SshPtyInteractArgs {
            host: "s".to_string(),
            session_id: "sess-1".to_string(),
            input: "test; rm -rf /".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = PtyInteractTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("'test; rm -rf /'"));
    }
}
