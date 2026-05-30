//! SSH Status Tool Handler
//!
//! Provides information about configured hosts and security settings.

use std::fmt::Write;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// SSH Status tool handler
#[mcp_tool(name = "ssh_status", group = "core", annotation = "read_only")]
#[derive(Default)]
pub struct SshStatusHandler;

impl SshStatusHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {},
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshStatusHandler {
    fn name(&self) -> &'static str {
        "ssh_status"
    }

    fn description(&self) -> &'static str {
        "Get the list of configured SSH hosts and their connection status. Call this first \
         to discover available host aliases before using any other tool. Returns plain text \
         with host names, hostnames, ports, users, auth type, and the security mode \
         (strict/permissive). The host aliases shown here are the values to pass as the \
         'host' parameter to all other ssh_* tools."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, _args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let mut result = String::new();
        result.push_str("Configured hosts:\n\n");

        for (name, host) in &ctx.config.hosts {
            let hostname = &host.hostname;
            let user = &host.user;
            let port = host.port;

            let _ = writeln!(result, "  {name} ({hostname}):");
            let _ = writeln!(result, "    User: {user}");
            let _ = writeln!(result, "    Port: {port}");

            let auth_type = match &host.auth {
                crate::config::AuthConfig::Key { path, .. } => format!("SSH Key ({path})"),
                crate::config::AuthConfig::Agent => "SSH Agent".to_string(),
                crate::config::AuthConfig::Password { .. } => "Password".to_string(),
                #[cfg(feature = "winrm")]
                crate::config::AuthConfig::Ntlm { domain, .. } => {
                    if let Some(d) = domain {
                        format!("NTLM ({d})")
                    } else {
                        "NTLM".to_string()
                    }
                }
                #[cfg(feature = "winrm")]
                crate::config::AuthConfig::Certificate { cert_path, .. } => {
                    format!("Certificate ({cert_path})")
                }
                #[cfg(feature = "winrm")]
                crate::config::AuthConfig::Kerberos => "Kerberos".to_string(),
            };
            let _ = writeln!(result, "    Auth: {auth_type}");

            if let Some(desc) = &host.description {
                let _ = writeln!(result, "    Description: {desc}");
            }
            result.push('\n');
        }

        let mode = &ctx.config.security.mode;
        let whitelist_count = ctx.config.security.whitelist.len();
        let blacklist_count = ctx.config.security.blacklist.len();

        let _ = writeln!(result, "Security mode: {mode:?}");
        let _ = writeln!(result, "Whitelist rules: {whitelist_count}");
        let _ = writeln!(result, "Blacklist rules: {blacklist_count}");

        Ok(ToolCallResult::text(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
    use crate::mcp::protocol::ToolContent;
    use crate::ports::mock::create_test_context_with_hosts;
    use std::collections::HashMap;

    fn get_text_content(result: &ToolCallResult) -> &str {
        match &result.content[0] {
            ToolContent::Text { text } => text,
            _ => panic!("Expected Text content"),
        }
    }

    #[tokio::test]
    async fn test_ssh_status_empty_hosts() {
        let handler = SshStatusHandler;
        let ctx = create_test_context_with_hosts(HashMap::new());

        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("Configured hosts:"));
        assert!(text.contains("Security mode: Standard"));
    }

    #[tokio::test]
    async fn test_ssh_status_with_hosts() {
        let handler = SshStatusHandler;
        let mut hosts = HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: Some("Test server".to_string()),
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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

        let ctx = create_test_context_with_hosts(hosts);
        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("server1"));
        assert!(text.contains("192.168.1.100"));
        assert!(text.contains("User: admin"));
        assert!(text.contains("Port: 22"));
        assert!(text.contains("SSH Key"));
        assert!(text.contains("Test server"));
    }

    #[tokio::test]
    async fn test_ssh_status_different_auth_types() {
        let handler = SshStatusHandler;
        let mut hosts = HashMap::new();

        hosts.insert(
            "key_host".to_string(),
            HostConfig {
                hostname: "host1".to_string(),
                port: 22,
                user: "user1".to_string(),
                auth: AuthConfig::Key {
                    path: "/path/to/key".to_string(),
                    passphrase: None,
                },
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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

        hosts.insert(
            "agent_host".to_string(),
            HostConfig {
                hostname: "host2".to_string(),
                port: 22,
                user: "user2".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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

        hosts.insert(
            "password_host".to_string(),
            HostConfig {
                hostname: "host3".to_string(),
                port: 2222,
                user: "user3".to_string(),
                auth: AuthConfig::Password {
                    password: crate::config::RedactedSecret::from("secret"),
                },
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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

        let ctx = create_test_context_with_hosts(hosts);
        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("SSH Key"));
        assert!(text.contains("SSH Agent"));
        assert!(text.contains("Password"));
    }

    #[test]
    fn test_schema() {
        let handler = SshStatusHandler;
        assert_eq!(handler.name(), "ssh_status");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_status");
    }

    #[test]
    fn test_schema_json_valid() {
        let handler = SshStatusHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        assert!(schema_json["required"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_handler_default_impl() {
        let handler = SshStatusHandler;
        assert_eq!(handler.name(), "ssh_status");
    }

    #[test]
    fn test_handler_description_discovery() {
        let handler = SshStatusHandler;
        // Description should mention using this tool first for discovery
        assert!(handler.description().contains("host"));
        assert!(handler.description().contains("first"));
    }
}
