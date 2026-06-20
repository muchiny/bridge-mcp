//! SSH LDAP User Info Tool Handler
//!
//! Looks up a user in an LDAP directory on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ldap::LdapCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshLdapUserInfoArgs {
    host: String,
    base_dn: String,
    username: String,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshLdapUserInfoArgs);

#[mcp_standard_tool(name = "ssh_ldap_user_info", group = "ldap", annotation = "read_only")]
pub struct LdapUserInfoTool;

impl StandardTool for LdapUserInfoTool {
    type Args = SshLdapUserInfoArgs;

    const NAME: &'static str = "ssh_ldap_user_info";

    const DESCRIPTION: &'static str = "Look up a specific user in an LDAP directory on a remote \
        host using ldapsearch (-x -LLL). Runs filter '(uid=<username>)' with scope sub and returns \
        all attributes. Use this instead of ssh_ldap_search when you know the exact uid; use \
        ssh_ldap_search for arbitrary filters or attribute projection. For group membership queries \
        use ssh_ldap_group_members. On Windows Active Directory hosts use ssh_ad_user_info instead \
        (PowerShell-based, richer AD attributes). Authentication uses the remote host's system \
        ldap.conf / SASL configuration (e.g. EXTERNAL, GSSAPI); no credentials are passed on the \
        command line.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "base_dn": {
                "type": "string",
                "description": "Base DN to search from (e.g. 'dc=example,dc=com')"
            },
            "username": {
                "type": "string",
                "description": "Username to look up (matched against uid attribute)"
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
        "required": ["host", "base_dn", "username"]
    }"#;

    fn build_command(args: &SshLdapUserInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(LdapCommandBuilder::build_user_info_command(
            &args.base_dn,
            &args.username,
            args.uri.as_deref(),
        ))
    }
}

/// Handler for the `ssh_ldap_user_info` tool.
pub type SshLdapUserInfoHandler = StandardToolHandler<LdapUserInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLdapUserInfoHandler::new();
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
        let handler = SshLdapUserInfoHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "base_dn": "dc=example,dc=com", "username": "jdoe"})),
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
        let handler = SshLdapUserInfoHandler::new();
        assert_eq!(handler.name(), "ssh_ldap_user_info");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("base_dn")));
        assert!(required.contains(&json!("username")));
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
        let args: SshLdapUserInfoArgs = serde_json::from_value(
            json!({"host": "s", "base_dn": "dc=example,dc=com", "username": "jdoe"}),
        )
        .unwrap();
        let host = test_host_config();
        let cmd = LdapUserInfoTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("ldapsearch"));
    }

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
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
            },
        );
        hosts
    }

    fn permissive_ctx(mock_out: crate::ssh::CommandOutput) -> crate::ports::ToolContext {
        use crate::config::SessionConfig;
        use crate::config::{Config, LimitsConfig, SecurityConfig, SecurityMode};
        use crate::domain::CommandHistory;
        use crate::domain::ExecuteCommandUseCase;
        use crate::domain::TunnelManager;
        use crate::domain::history::HistoryConfig;
        use crate::ports::ExecutorRouter;
        use crate::security::AuditLogger;
        use crate::security::RateLimiter;
        use crate::security::{CommandValidator, Sanitizer};
        use crate::ssh::SessionManager;
        use std::sync::Arc;
        let sec = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: Vec::new(),
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts: server1_hosts(),
            security: sec.clone(),
            limits: LimitsConfig::default(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&sec));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));
        crate::ports::ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::mock(mock_out)),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            pending_requests: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshLdapUserInfoHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(
                Some(
                    json!({"host": "server1", "base_dn": "dc=example,dc=com", "username": "jdoe"}),
                ),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
