//! Handler for the `ssh_webhook_send` tool.
//!
//! Sends a webhook POST request from a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::chatops::ChatOpsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshWebhookSendArgs {
    /// Target host name from configuration.
    host: String,
    /// Webhook URL (must start with https://).
    url: String,
    /// JSON payload to send.
    payload: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshWebhookSendArgs);

#[mcp_standard_tool(name = "ssh_webhook_send", group = "chatops", annotation = "mutating")]
pub struct WebhookSendTool;

impl StandardTool for WebhookSendTool {
    type Args = SshWebhookSendArgs;

    const NAME: &'static str = "ssh_webhook_send";

    const DESCRIPTION: &'static str = "Send a caller-supplied JSON payload via webhook POST from a remote host. \
        The payload is transmitted exactly as provided — no envelope, hostname, or timestamp is added. \
        Use this tool when you control the complete JSON body (CI/CD events, signed payloads, structured data). \
        For simple text alerts that should be auto-stamped with hostname and timestamp, use ssh_notify instead. \
        Note: the URL parameter for this tool is named `url` (not `webhook_url`). \
        Returns the response body and HTTP status code.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "url": {
                        "type": "string",
                        "description": "Webhook endpoint URL. Must use HTTPS (http:// is rejected by the server). Note: this param is named `url`; ssh_notify uses `webhook_url`. Example: https://hooks.slack.com/services/T000/B000/xxxx"
                    },
                    "payload": {
                        "type": "string",
                        "description": "JSON payload to send (max 10000 characters)"
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
                "required": ["host", "url", "payload"]
            }"#;

    fn build_command(args: &SshWebhookSendArgs, _host_config: &HostConfig) -> Result<String> {
        ChatOpsCommandBuilder::build_webhook_command(&args.url, &args.payload)
    }
}

/// Handler for the `ssh_webhook_send` tool.
pub type SshWebhookSendHandler = StandardToolHandler<WebhookSendTool>;

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
        let handler = SshWebhookSendHandler::new();
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
        let handler = SshWebhookSendHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "url": "https://hooks.slack.com/services/T/B/X",
                    "payload": "{\"text\":\"hello\"}"
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
        let handler = SshWebhookSendHandler::new();
        assert_eq!(handler.name(), "ssh_webhook_send");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_webhook_send");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("url")));
        assert!(required.contains(&json!("payload")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "url": "https://hooks.slack.com/services/T/B/X",
            "payload": "{\"text\":\"deploy complete\"}",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/webhook.txt"
        });
        let args: SshWebhookSendArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.url.starts_with("https://"));
        assert!(args.payload.contains("deploy"));
        assert_eq!(args.timeout_seconds, Some(15));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "url": "https://example.com/webhook",
            "payload": "{\"text\":\"test\"}"
        });
        let args: SshWebhookSendArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWebhookSendHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "url": "https://example.com/hook",
            "payload": "{}"
        });
        let args: SshWebhookSendArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshWebhookSendArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshWebhookSendHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "url": 456, "payload": 789})), &ctx)
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
        let args = SshWebhookSendArgs {
            host: "s".to_string(),
            url: "https://hooks.slack.com/services/T/B/X".to_string(),
            payload: "{\"text\":\"hello\"}".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = WebhookSendTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("curl -s -X POST"));
        assert!(cmd.contains("Content-Type: application/json"));
    }

    #[test]
    fn test_build_command_invalid_url() {
        let args = SshWebhookSendArgs {
            host: "s".to_string(),
            url: "http://insecure.com".to_string(),
            payload: "{\"text\":\"hello\"}".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = WebhookSendTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
