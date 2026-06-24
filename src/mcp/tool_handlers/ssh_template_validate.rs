//! Handler for the `ssh_template_validate` tool.
//!
//! Validates a service's configuration on a remote host by running
//! the appropriate config-test command.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::templates::{
    TemplateCommandBuilder, validate_dest_path, validate_service,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshTemplateValidateArgs {
    /// Target host name from configuration.
    host: String,
    /// Service to validate (nginx, apache, postgresql, mysql, redis).
    service: String,
    /// Optional path to the configuration file to validate.
    #[serde(default)]
    config_path: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshTemplateValidateArgs);

#[mcp_standard_tool(
    name = "ssh_template_validate",
    group = "templates",
    annotation = "read_only"
)]
pub struct TemplateValidateTool;

impl StandardTool for TemplateValidateTool {
    type Args = SshTemplateValidateArgs;

    const NAME: &'static str = "ssh_template_validate";

    const DESCRIPTION: &'static str = "Validate a service's configuration on a Linux host by \
        running its native config-test command: nginx -t, apachectl configtest, pg_isready, \
        mysqld --validate-config, or redis-cli ping. Use after ssh_template_apply to confirm \
        the deployed configuration is syntactically correct. Discover template names first \
        with ssh_template_list.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "service": {
                        "type": "string",
                        "description": "Service to validate; must be one of the five supported values.",
                        "enum": ["nginx", "apache", "postgresql", "mysql", "redis"]
                    },
                    "config_path": {
                        "type": "string",
                        "description": "Optional path to the configuration file to validate"
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
                "required": ["host", "service"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn validate(args: &SshTemplateValidateArgs, _host_config: &HostConfig) -> Result<()> {
        validate_service(&args.service)?;
        if let Some(path) = &args.config_path {
            validate_dest_path(path)?;
        }
        Ok(())
    }

    fn build_command(args: &SshTemplateValidateArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(TemplateCommandBuilder::build_template_validate_command(
            &args.service,
            args.config_path.as_deref(),
        ))
    }
}

/// Handler for the `ssh_template_validate` tool.
pub type SshTemplateValidateHandler = StandardToolHandler<TemplateValidateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTemplateValidateHandler::new();
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
        let handler = SshTemplateValidateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "service": "nginx"})),
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
        let handler = SshTemplateValidateHandler::new();
        assert_eq!(handler.name(), "ssh_template_validate");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_template_validate");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("service")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "service": "nginx",
            "config_path": "/etc/nginx/nginx.conf",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/validate.txt"
        });
        let args: SshTemplateValidateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service, "nginx");
        assert_eq!(args.config_path.as_deref(), Some("/etc/nginx/nginx.conf"));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/validate.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "service": "nginx"
        });
        let args: SshTemplateValidateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service, "nginx");
        assert!(args.config_path.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTemplateValidateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("config_path"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "service": "nginx"
        });
        let args: SshTemplateValidateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshTemplateValidateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTemplateValidateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "service": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_nginx() {
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
        let args = SshTemplateValidateArgs {
            host: "s".to_string(),
            service: "nginx".to_string(),
            config_path: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TemplateValidateTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "nginx -t");
    }

    #[test]
    fn test_build_command_mysql_with_path() {
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
        let args = SshTemplateValidateArgs {
            host: "s".to_string(),
            service: "mysql".to_string(),
            config_path: Some("/etc/mysql/my.cnf".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TemplateValidateTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("--validate-config"));
        assert!(cmd.contains("--defaults-file="));
    }
}
