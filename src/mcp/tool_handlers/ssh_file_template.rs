//! SSH File Template Tool Handler
//!
//! Renders a template file using environment variable substitution (envsubst).

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::file_advanced::FileAdvancedCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshFileTemplateArgs {
    host: String,
    template_path: String,
    output_path: String,
    #[serde(default)]
    variables: Option<HashMap<String, String>>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshFileTemplateArgs);

#[mcp_standard_tool(
    name = "ssh_file_template",
    group = "file_ops",
    annotation = "mutating"
)]
pub struct FileTemplateTool;

impl StandardTool for FileTemplateTool {
    type Args = SshFileTemplateArgs;

    const NAME: &'static str = "ssh_file_template";

    const DESCRIPTION: &'static str = "Render a template file using environment variable \
        substitution (envsubst). Variables in the template are replaced with provided values.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "template_path": {
                "type": "string",
                "description": "Absolute path to the template file on the remote host"
            },
            "output_path": {
                "type": "string",
                "description": "Absolute path for the rendered output file"
            },
            "variables": {
                "type": "object",
                "description": "Key-value pairs of template variables to substitute",
                "additionalProperties": {
                    "type": "string"
                }
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
        "required": ["host", "template_path", "output_path"]
    }"#;

    fn scoped_paths(args: &SshFileTemplateArgs) -> Vec<&str> {
        vec![&args.template_path, &args.output_path]
    }

    fn build_command(args: &SshFileTemplateArgs, _host_config: &HostConfig) -> Result<String> {
        let vars_vec: Vec<(String, String)> = args
            .variables
            .as_ref()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        FileAdvancedCommandBuilder::build_template_command(
            &args.template_path,
            &args.output_path,
            &vars_vec,
        )
    }
}

pub type SshFileTemplateHandler = StandardToolHandler<FileTemplateTool>;

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
        let handler = SshFileTemplateHandler::new();
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
        let handler = SshFileTemplateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "template_path": "/etc/template.conf",
                    "output_path": "/etc/output.conf"
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshFileTemplateHandler::new();
        assert_eq!(handler.name(), "ssh_file_template");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("template_path")));
        assert!(required.contains(&json!("output_path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "template_path": "/etc/nginx/template.conf",
            "output_path": "/etc/nginx/site.conf",
            "variables": {"SERVER_NAME": "example.com", "PORT": "8080"},
            "timeout_seconds": 30
        });
        let args: SshFileTemplateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.template_path, "/etc/nginx/template.conf");
        assert_eq!(args.output_path, "/etc/nginx/site.conf");
        let vars = args.variables.unwrap();
        assert_eq!(vars.get("SERVER_NAME").unwrap(), "example.com");
        assert_eq!(vars.get("PORT").unwrap(), "8080");
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({
            "host": "server1",
            "template_path": "/etc/template",
            "output_path": "/etc/output"
        });
        let args: SshFileTemplateArgs = serde_json::from_value(json).unwrap();
        assert!(args.variables.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_build_command() {
        let mut variables = HashMap::new();
        variables.insert("SERVER_NAME".to_string(), "example.com".to_string());
        let args = SshFileTemplateArgs {
            host: "server1".to_string(),
            template_path: "/etc/nginx/template.conf".to_string(),
            output_path: "/etc/nginx/site.conf".to_string(),
            variables: Some(variables),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileTemplateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("envsubst"));
        assert!(cmd.contains("SERVER_NAME"));
        assert!(cmd.contains("export"));
    }
}
