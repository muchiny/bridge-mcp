//! Handler for the `ssh_selinux_booleans` tool.
//!
//! List or set `SELinux` booleans on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::security_modules::SecurityModulesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshSelinuxBooleansArgs {
    host: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshSelinuxBooleansArgs);

#[mcp_standard_tool(
    name = "ssh_selinux_booleans",
    group = "security_modules",
    annotation = "mutating"
)]
pub struct SelinuxBooleansTool;

impl StandardTool for SelinuxBooleansTool {
    type Args = SshSelinuxBooleansArgs;

    const NAME: &'static str = "ssh_selinux_booleans";

    const DESCRIPTION: &'static str = "List or set SELinux booleans (policy tunables) on a remote \
        host. Omit both name and value to list all booleans (getsebool -a). Supply name alone \
        to query a single boolean. Supply name and value (true/false) to persistently toggle \
        one boolean (setsebool -P). Use ssh_selinux_status first to confirm SELinux is enabled \
        on the host. This tool is SELinux-specific; AppArmor hosts have no equivalent (use \
        ssh_apparmor_profiles to inspect AppArmor enforcement state).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "name": {
                "type": "string",
                "description": "SELinux boolean name to query or set (e.g., httpd_can_network_connect). Omit to list all booleans."
            },
            "value": {
                "type": "boolean",
                "description": "New value for the boolean (true=on, false=off). Requires 'name' to be specified. Setting is persistent across reboots (setsebool -P)."
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;

    fn build_command(args: &SshSelinuxBooleansArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(
            SecurityModulesCommandBuilder::build_selinux_booleans_command(
                args.name.as_deref(),
                args.value,
            ),
        )
    }
}

/// Handler for the `ssh_selinux_booleans` tool.
pub type SshSelinuxBooleansHandler = StandardToolHandler<SelinuxBooleansTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSelinuxBooleansHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshSelinuxBooleansHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshSelinuxBooleansHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_selinux_booleans");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "name": "httpd_can_network_connect",
            "value": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshSelinuxBooleansArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, Some("httpd_can_network_connect".to_string()));
        assert_eq!(args.value, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshSelinuxBooleansArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.name.is_none());
        assert!(args.value.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshSelinuxBooleansHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h"});
        let args: SshSelinuxBooleansArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshSelinuxBooleansArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshSelinuxBooleansArgs>(json);
        assert!(result.is_err());
    }

    fn test_host_config() -> crate::config::HostConfig {
        crate::config::HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: crate::config::HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: crate::config::OsType::default(),
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
    fn test_build_command_defaults() {
        let args: SshSelinuxBooleansArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = SelinuxBooleansTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_build_command_with_name_and_value() {
        let args: SshSelinuxBooleansArgs = serde_json::from_value(json!({
            "host": "s",
            "name": "httpd_can_network_connect",
            "value": true
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = SelinuxBooleansTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("httpd_can_network_connect"));
    }
}
