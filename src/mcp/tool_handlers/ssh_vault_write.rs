use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::vault::VaultCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshVaultWriteArgs {
    host: String,
    path: String,
    /// FIND-030: each `key=value` pair is wrapped in `Zeroizing<String>` so
    /// the heap allocation is wiped when this `Args` instance is dropped.
    /// Local heap residency was gratuitous — the secret only needs to live
    /// long enough to build the remote `vault kv put` command.
    data: Vec<zeroize::Zeroizing<String>>,
    vault_addr: Option<String>,
    mount: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshVaultWriteArgs);

#[mcp_standard_tool(name = "ssh_vault_write", group = "vault", annotation = "mutating")]
pub struct VaultWriteTool;

impl StandardTool for VaultWriteTool {
    type Args = SshVaultWriteArgs;

    const NAME: &'static str = "ssh_vault_write";

    const DESCRIPTION: &'static str = "Write a secret to HashiCorp Vault on a remote host. Creates or updates secret data at \
        the given path. Use ssh_vault_list to browse existing paths and ssh_vault_read to \
        verify after writing.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "path": {
                        "type": "string",
                        "description": "Secret path in Vault"
                    },
                    "data": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Key-value pairs as 'key=value' strings"
                    },
                    "vault_addr": {
                        "type": "string",
                        "description": "Vault server address (default: from VAULT_ADDR env)"
                    },
                    "mount": {
                        "type": "string",
                        "description": "Secrets engine mount path"
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Command timeout in seconds"
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters"
                    },
                    "save_output": {
                        "type": "string",
                        "description": "File path to save full output"
                    }
                },
                "required": ["host", "path", "data"]
            }"#;

    fn build_command(args: &SshVaultWriteArgs, _host_config: &HostConfig) -> Result<String> {
        VaultCommandBuilder::build_write_command(
            &args.path,
            &args.data,
            args.vault_addr.as_deref(),
            args.mount.as_deref(),
        )
    }
}

/// Handler for the `ssh_vault_write` tool.
pub type SshVaultWriteHandler = StandardToolHandler<VaultWriteTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshVaultWriteHandler::new();
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
        let handler = SshVaultWriteHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "secret/data/myapp", "data": ["key=value"]})),
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
        let handler = SshVaultWriteHandler::new();
        assert_eq!(handler.name(), "ssh_vault_write");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_vault_write");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
        assert!(required.contains(&json!("data")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "path": "secret/data/myapp",
            "data": ["username=admin", "password=secret123"],
            "vault_addr": "https://vault.example.com:8200",
            "mount": "secret",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/vault_write.txt"
        });
        let args: SshVaultWriteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "secret/data/myapp");
        // FIND-030: data is Vec<Zeroizing<String>>; deref to compare as &str.
        let data_strs: Vec<&str> = args.data.iter().map(|s| s.as_str()).collect();
        assert_eq!(data_strs, vec!["username=admin", "password=secret123"]);
        assert_eq!(
            args.vault_addr.as_deref(),
            Some("https://vault.example.com:8200")
        );
        assert_eq!(args.mount.as_deref(), Some("secret"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/vault_write.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "path": "secret/data/myapp", "data": ["key=value"]});
        let args: SshVaultWriteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "secret/data/myapp");
        let data_strs: Vec<&str> = args.data.iter().map(|s| s.as_str()).collect();
        assert_eq!(data_strs, vec!["key=value"]);
        assert!(args.vault_addr.is_none());
        assert!(args.mount.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshVaultWriteHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("vault_addr"));
        assert!(properties.contains_key("mount"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "path": "secret/data/myapp", "data": ["key=value"]});
        let args: SshVaultWriteArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshVaultWriteArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshVaultWriteHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "path": 456, "data": "not_an_array"})),
                &ctx,
            )
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
        let args: SshVaultWriteArgs = serde_json::from_value(
            json!({"host": "s", "path": "secret/data/myapp", "data": ["key=value"]}),
        )
        .unwrap();
        let host = test_host_config();
        let cmd = VaultWriteTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("vault"));
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
        let handler = SshVaultWriteHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(
                Some(
                    json!({"host": "server1", "path": "secret/data/myapp", "data": ["key=value"]}),
                ),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
