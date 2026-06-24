//! Handler for the `ssh_notify` tool.
//!
//! Sends a notification message via webhook from a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::chatops::ChatOpsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshNotifyArgs {
    /// Target host name from configuration.
    host: String,
    /// Notification message text.
    message: String,
    /// Webhook URL for the notification (must start with https://).
    webhook_url: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshNotifyArgs);

#[mcp_standard_tool(name = "ssh_notify", group = "chatops", annotation = "mutating")]
pub struct NotifyTool;

impl StandardTool for NotifyTool {
    type Args = SshNotifyArgs;

    const NAME: &'static str = "ssh_notify";

    const DESCRIPTION: &'static str = "Send a plain-text notification via webhook from a remote host. \
        Wraps the message in a fixed JSON envelope with the remote hostname and a UTC timestamp \
        ({\"text\":\"...\",\"hostname\":\"...\",\"timestamp\":\"...\"}) and POSTs it to the webhook URL. \
        Use this tool when you have a simple text alert and want the server to stamp it automatically. \
        For custom JSON payloads (CI/CD bodies, signed events, structured data) use ssh_webhook_send instead. \
        Works with Slack, Teams, and Discord incoming-webhook URLs.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "message": {
                        "type": "string",
                        "description": "Notification message text"
                    },
                    "webhook_url": {
                        "type": "string",
                        "description": "Webhook endpoint URL. Must use HTTPS (http:// is rejected by the server). Example: https://hooks.slack.com/services/T000/B000/xxxx"
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
                "required": ["host", "message", "webhook_url"]
            }"#;

    fn build_command(args: &SshNotifyArgs, _host_config: &HostConfig) -> Result<String> {
        ChatOpsCommandBuilder::build_notify_command(&args.message, &args.webhook_url)
    }
}

/// Handler for the `ssh_notify` tool.
pub type SshNotifyHandler = StandardToolHandler<NotifyTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshNotifyHandler::new();
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
        let handler = SshNotifyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "message": "Server restarted",
                    "webhook_url": "https://hooks.slack.com/services/T/B/X"
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
        let handler = SshNotifyHandler::new();
        assert_eq!(handler.name(), "ssh_notify");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_notify");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("message")));
        assert!(required.contains(&json!("webhook_url")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "message": "Deploy complete on production",
            "webhook_url": "https://hooks.slack.com/services/T/B/X",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/notify.txt"
        });
        let args: SshNotifyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.message, "Deploy complete on production");
        assert!(args.webhook_url.starts_with("https://"));
        assert_eq!(args.timeout_seconds, Some(15));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "message": "test",
            "webhook_url": "https://example.com/webhook"
        });
        let args: SshNotifyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.message, "test");
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNotifyHandler::new();
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
            "message": "hello",
            "webhook_url": "https://example.com/hook"
        });
        let args: SshNotifyArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshNotifyArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshNotifyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "message": 456, "webhook_url": 789})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    fn test_host_config() -> HostConfig {
        HostConfig {
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
        }
    }

    #[test]
    fn test_build_command_valid() {
        let args = SshNotifyArgs {
            host: "s".to_string(),
            message: "Server restarted".to_string(),
            webhook_url: "https://hooks.slack.com/services/T/B/X".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = NotifyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("curl -s -X POST"));
        assert!(cmd.contains("hostname"));
        assert!(cmd.contains("timestamp"));
    }

    #[test]
    fn test_build_command_invalid_url() {
        let args = SshNotifyArgs {
            host: "s".to_string(),
            message: "hello".to_string(),
            webhook_url: "http://insecure.com".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = NotifyTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
