//! SSH LDAP Add Tool Handler
//!
//! Adds an entry to an LDAP directory on a remote host via SSH using LDIF format.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ldap::LdapCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshLdapAddArgs {
    host: String,
    ldif: String,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshLdapAddArgs);

#[mcp_standard_tool(name = "ssh_ldap_add", group = "ldap", annotation = "mutating")]
pub struct LdapAddTool;

impl StandardTool for LdapAddTool {
    type Args = SshLdapAddArgs;

    const NAME: &'static str = "ssh_ldap_add";

    const DESCRIPTION: &'static str = "Add a new entry to an LDAP directory on a remote host \
        using LDIF format via ldapadd. Use for new entries only — fails if the DN already \
        exists; to update an existing entry use ssh_ldap_modify instead. Do not include \
        'changetype: add' in the LDIF — ldapadd treats all entries as additions implicitly \
        (including changetype causes errors). Authentication uses the remote host's system \
        ldap.conf / SASL configuration (e.g. EXTERNAL, GSSAPI); no credentials are passed \
        on the command line.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "ldif": {
                "type": "string",
                "description": "LDIF content for the entry to add (e.g. 'dn: cn=test,dc=example,dc=com\nobjectClass: top'). Do not include 'changetype: add' — it is implied."
            },
            "uri": {
                "type": "string",
                "description": "LDAP URI (e.g. 'ldap://ldap.example.com'). Uses system default if omitted."
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "ldif"]
    }"#;

    fn build_command(args: &SshLdapAddArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(LdapCommandBuilder::build_add_command(
            &args.ldif,
            args.uri.as_deref(),
        ))
    }
}

/// Handler for the `ssh_ldap_add` tool.
pub type SshLdapAddHandler = StandardToolHandler<LdapAddTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLdapAddHandler::new();
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
        let handler = SshLdapAddHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "ldif": "dn: cn=test\nobjectClass: top"})),
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
        let handler = SshLdapAddHandler::new();
        assert_eq!(handler.name(), "ssh_ldap_add");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("ldif")));
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
        let args: SshLdapAddArgs =
            serde_json::from_value(json!({"host": "s", "ldif": "dn: cn=test\nobjectClass: top"}))
                .unwrap();
        let host = test_host_config();
        let cmd = LdapAddTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("ldapadd"));
    }
}
