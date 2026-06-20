//! SSH Redis Info Tool Handler
//!
//! Gets Redis server information on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::redis::RedisCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshRedisInfoArgs {
    host: String,
    redis_host: Option<String>,
    redis_port: Option<u16>,
    section: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshRedisInfoArgs);

#[mcp_standard_tool(name = "ssh_redis_info", group = "redis", annotation = "read_only")]
pub struct RedisInfoTool;

impl StandardTool for RedisInfoTool {
    type Args = SshRedisInfoArgs;

    const NAME: &'static str = "ssh_redis_info";

    const DESCRIPTION: &'static str = "Get Redis server information (INFO) on a remote host. \
        Use this for structured server diagnostics: memory usage, connected clients, replication \
        topology, persistence state, CPU, keyspace, and cluster status. Filter by section to \
        reduce output. Auth is sourced from the REDISCLI_AUTH environment variable or \
        ~/.redisclirc on the remote host. Use ssh_redis_keys to discover keys with SCAN, or \
        ssh_redis_cli for arbitrary read/write commands.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "redis_host": {
                "type": "string",
                "description": "Redis server hostname (default: localhost)"
            },
            "redis_port": {
                "type": "integer",
                "description": "Redis server port (default: 6379)",
                "default": 6379,
                "minimum": 1,
                "maximum": 65535
            },
            "section": {
                "type": "string",
                "description": "INFO section to retrieve (default: all sections). Use 'all' for the full report or 'everything' to include module/latency sections.",
                "enum": ["server", "clients", "memory", "persistence", "stats", "replication", "cpu", "commandstats", "errorstats", "latencystats", "cluster", "modules", "keyspace", "all", "everything"]
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds",
                "minimum": 1
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters",
                "minimum": 100
            },
            "save_output": {
                "type": "string",
                "description": "File path to save full output"
            }
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshRedisInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(RedisCommandBuilder::build_info_command(
            args.redis_host.as_deref(),
            args.redis_port,
            args.section.as_deref(),
        ))
    }
}

/// Handler for the `ssh_redis_info` tool.
pub type SshRedisInfoHandler = StandardToolHandler<RedisInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRedisInfoHandler::new();
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
        let handler = SshRedisInfoHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshRedisInfoHandler::new();
        assert_eq!(handler.name(), "ssh_redis_info");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_redis_info");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "redis_host": "redis.local",
            "redis_port": 6380,
            "section": "memory",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/redis_info.txt"
        });
        let args: SshRedisInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.redis_host.as_deref(), Some("redis.local"));
        assert_eq!(args.redis_port, Some(6380));
        assert_eq!(args.section.as_deref(), Some("memory"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/redis_info.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshRedisInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.redis_host.is_none());
        assert!(args.redis_port.is_none());
        assert!(args.section.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRedisInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("redis_host"));
        assert!(properties.contains_key("redis_port"));
        assert!(properties.contains_key("section"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost"});
        let args: SshRedisInfoArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshRedisInfoArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshRedisInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
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
        let args: SshRedisInfoArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = RedisInfoTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("redis"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshRedisInfoArgs = serde_json::from_value(json!({
            "host": "s",
            "redis_host": "redis.local",
            "redis_port": 6380,
            "section": "memory"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = RedisInfoTool::build_command(&args, &host).unwrap();
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
        let handler = SshRedisInfoHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
