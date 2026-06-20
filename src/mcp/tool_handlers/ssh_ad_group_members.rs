//! Handler for the `ssh_ad_group_members` tool.
//!
//! List members of an Active Directory group with name, SAM account name, and object class.
//! Requires the AD `PowerShell` module.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::active_directory::{
    ActiveDirectoryCommandBuilder, validate_ad_identity,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshAdGroupMembersArgs {
    host: String,
    group: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshAdGroupMembersArgs);

#[mcp_standard_tool(
    name = "ssh_ad_group_members",
    group = "active_directory",
    annotation = "read_only"
)]
pub struct AdGroupMembersTool;

impl StandardTool for AdGroupMembersTool {
    type Args = SshAdGroupMembersArgs;

    const NAME: &'static str = "ssh_ad_group_members";

    const DESCRIPTION: &'static str = "List members of an Active Directory group with name, SAM account name, and object \
        class using Get-ADGroupMember on a Windows DC. Requires the AD PowerShell module (RSAT). \
        Use this tool (not ssh_ldap_group_members) when the host is a Windows DC with the AD \
        PowerShell module installed — it returns AD-typed objects including nested group entries \
        (objectClass=group) and handles the full AD object model. For raw LDAP queries or \
        non-Windows hosts, use ssh_ldap_group_members instead. \
        Large groups (e.g. Domain Users) can produce thousands of rows; use save_output to \
        persist the full result to a file on the remote host when output is truncated.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "group"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml — must be a Windows host (use ssh_status to list hosts)"
            },
            "group": {
                "type": "string",
                "description": "Name of the AD group (e.g., Domain Admins, IT-Staff)"
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

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshAdGroupMembersArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(ActiveDirectoryCommandBuilder::build_group_members_command(
            &args.group,
        ))
    }

    fn validate(args: &SshAdGroupMembersArgs, _host_config: &HostConfig) -> Result<()> {
        validate_ad_identity(&args.group)?;
        Ok(())
    }
}

/// Handler for the `ssh_ad_group_members` tool.
pub type SshAdGroupMembersHandler = StandardToolHandler<AdGroupMembersTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAdGroupMembersHandler::new();
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
        let handler = SshAdGroupMembersHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "group": "Domain Admins"})),
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
        let handler = SshAdGroupMembersHandler::new();
        assert_eq!(handler.name(), "ssh_ad_group_members");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ad_group_members");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("group")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "windc01",
            "group": "Domain Admins",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/members.txt"
        });
        let args: SshAdGroupMembersArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "windc01");
        assert_eq!(args.group, "Domain Admins");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/members.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "windc01", "group": "Domain Admins"});
        let args: SshAdGroupMembersArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "windc01");
        assert_eq!(args.group, "Domain Admins");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAdGroupMembersHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "windc01", "group": "IT-Staff"});
        let args: SshAdGroupMembersArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAdGroupMembersArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAdGroupMembersHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "group": "Admins"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
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
            os_type: crate::config::OsType::Windows,
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
        let args: SshAdGroupMembersArgs =
            serde_json::from_value(json!({"host": "s", "group": "DomainAdmins"})).unwrap();
        let host = test_host_config();
        let cmd = AdGroupMembersTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn win_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "winhost".to_string(),
            HostConfig {
                hostname: "10.0.0.1".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Windows,
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
            },
        );
        hosts
    }
    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshAdGroupMembersHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(
                Some(json!({"host": "winhost", "group": "Domain Admins"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
