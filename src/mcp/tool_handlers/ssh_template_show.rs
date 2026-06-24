//! Handler for the `ssh_template_show` tool.
//!
//! Shows the content of a configuration template on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::templates::{TemplateCommandBuilder, validate_template_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshTemplateShowArgs {
    /// Target host name from configuration.
    host: String,
    /// Name of the template to show.
    template_name: String,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshTemplateShowArgs);

#[mcp_standard_tool(
    name = "ssh_template_show",
    group = "templates",
    annotation = "read_only"
)]
pub struct TemplateShowTool;

impl StandardTool for TemplateShowTool {
    type Args = SshTemplateShowArgs;

    const NAME: &'static str = "ssh_template_show";

    const DESCRIPTION: &'static str = "Show the content of one of the six built-in service \
        configuration templates on a Linux host. Call ssh_template_list first to see all \
        available names (nginx-reverse-proxy, nginx-static, apache-vhost, postgresql-config, \
        mysql-config, redis-config). After reviewing, use ssh_template_diff to preview \
        changes and ssh_template_apply to deploy the template.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "template_name": {
                        "type": "string",
                        "description": "Name of the template to show. Built-in names: nginx-reverse-proxy, nginx-static, apache-vhost, postgresql-config, mysql-config, redis-config. Custom names are accepted if they contain only alphanumerics, hyphens, and underscores."
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
                "required": ["host", "template_name"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn validate(args: &SshTemplateShowArgs, _host_config: &HostConfig) -> Result<()> {
        validate_template_name(&args.template_name)
    }

    fn build_command(args: &SshTemplateShowArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(TemplateCommandBuilder::build_template_show_command(
            &args.template_name,
        ))
    }
}

/// Handler for the `ssh_template_show` tool.
pub type SshTemplateShowHandler = StandardToolHandler<TemplateShowTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTemplateShowHandler::new();
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
        let handler = SshTemplateShowHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "template_name": "nginx-static"})),
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
        let handler = SshTemplateShowHandler::new();
        assert_eq!(handler.name(), "ssh_template_show");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_template_show");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("template_name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "template_name": "nginx-reverse-proxy",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/template.txt"
        });
        let args: SshTemplateShowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.template_name, "nginx-reverse-proxy");
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/template.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "template_name": "redis-config"
        });
        let args: SshTemplateShowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.template_name, "redis-config");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTemplateShowHandler::new();
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
            "template_name": "nginx-static"
        });
        let args: SshTemplateShowArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshTemplateShowArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTemplateShowHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "template_name": 456})), &ctx)
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
        let args = SshTemplateShowArgs {
            host: "s".to_string(),
            template_name: "nginx-static".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TemplateShowTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("nginx-static"));
    }
}
