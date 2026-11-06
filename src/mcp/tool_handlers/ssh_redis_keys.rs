//! SSH Redis Keys Tool Handler
//!
//! Scans Redis keys on a remote host using SCAN (non-blocking).

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::redis::RedisCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshRedisKeysArgs {
    host: String,
    pattern: Option<String>,
    count: Option<u32>,
    redis_host: Option<String>,
    redis_password: Option<String>,
    redis_port: Option<u16>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshRedisKeysArgs);

#[mcp_standard_tool(name = "ssh_redis_keys", group = "redis", annotation = "read_only")]
pub struct RedisKeysTool;

impl StandardTool for RedisKeysTool {
    type Args = SshRedisKeysArgs;

    const NAME: &'static str = "ssh_redis_keys";

    const DESCRIPTION: &'static str = "Scan Redis keys on a remote host using the non-blocking \
        SCAN iterator (redis-cli --scan --pattern). Prefer this over ssh_redis_cli with KEYS \
        because SCAN does not block the server on large keyspaces. Use the pattern param \
        (glob-style, default: *) to narrow results. \
        Auth: the REDISCLI_AUTH environment variable of the SSH host is used only for the \
        local server (redis_host omitted, localhost or a loopback address); for any other \
        redis_host give redis_password, or omit it for a server without a password. \
        Use ssh_redis_cli to \
        read/write specific key values, or ssh_redis_info for server-level stats.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "pattern": {
                "type": "string",
                "description": "Key pattern to match (default: *)"
            },
            "count": {
                "type": "integer",
                "description": "Hint for the number of keys Redis should return per SCAN iteration (passed as --count; higher values speed up full scans at the cost of larger individual calls)"
            },
            "redis_host": {
                "type": "string",
                "description": "Redis server host name or IP address (default: the local server). Letters, digits and . - _ : % only, at most 253 bytes. The REDISCLI_AUTH environment variable of the SSH host is used only when redis_host is omitted, localhost or a loopback address; for any other server it is not sent."
            },
            "redis_password": {
                "type": "string",
                "description": "Password for the server named by redis_host. It is sent to that server only and is not an argument of redis-cli (it reaches it on standard input), but it is part of the command line the remote shell runs (readable with ps on the target during the call) and of the command text in the bridge's audit log and history. Optional: omit it for a server without a password, or for a local server whose password the SSH host already provides in REDISCLI_AUTH. Not empty, no line breaks or other control characters, at most 1024 bytes."
            },
            "redis_port": {
                "type": "integer",
                "description": "Redis server port (default: 6379)",
                "default": 6379,
                "minimum": 1,
                "maximum": 65535
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
        "required": ["host"]
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshRedisKeysArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(RedisCommandBuilder::build_keys_command(
            args.redis_host.as_deref(),
            args.redis_port,
            args.pattern.as_deref(),
            args.count,
            args.redis_password.as_deref(),
        ))
    }

    fn validate(args: &SshRedisKeysArgs, _host_config: &HostConfig) -> Result<()> {
        RedisCommandBuilder::validate_connection(
            args.redis_host.as_deref(),
            args.redis_password.as_deref(),
        )
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshRedisKeysArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Redis Keys");
        for h in &parsed.headers {
            tbl = tbl.column(h, h.to_uppercase());
        }
        for row in &parsed.rows {
            let first = row.first().map_or("", String::as_str);
            if first.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            for (i, h) in parsed.headers.iter().enumerate() {
                obj.insert(
                    h.clone(),
                    serde_json::Value::String(row.get(i).map_or_else(String::new, Clone::clone)),
                );
            }
            tbl = tbl.row(serde_json::Value::Object(obj));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_redis_keys",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_redis_keys` tool.
pub type SshRedisKeysHandler = StandardToolHandler<RedisKeysTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRedisKeysHandler::new();
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
        let handler = SshRedisKeysHandler::new();
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
        let handler = SshRedisKeysHandler::new();
        assert_eq!(handler.name(), "ssh_redis_keys");
        assert_ne!(handler.description(), "");
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_redis_keys");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "pattern": "user:*",
            "count": 100,
            "redis_host": "redis.local",
            "redis_port": 6380,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/keys.txt"
        });
        let args: SshRedisKeysArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.pattern.as_deref(), Some("user:*"));
        assert_eq!(args.count, Some(100));
        assert_eq!(args.redis_host.as_deref(), Some("redis.local"));
        assert_eq!(args.redis_port, Some(6380));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/keys.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshRedisKeysArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.pattern.is_none());
        assert!(args.count.is_none());
        assert!(args.redis_host.is_none());
        assert!(args.redis_port.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRedisKeysHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("pattern"));
        assert!(properties.contains_key("count"));
        assert!(properties.contains_key("redis_host"));
        assert!(properties.contains_key("redis_port"));
        assert!(properties.contains_key("redis_password"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost"});
        let args: SshRedisKeysArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshRedisKeysArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshRedisKeysHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
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
            mrtr: crate::ports::MrtrSlot::default(),
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
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshRedisKeysHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshRedisKeysArgs =
            serde_json::from_value(json!({"host": "server1", "pattern": "user:*"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "user:1000\nuser:1001\nsession:abc\n";
        let result = RedisKeysTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshRedisKeysArgs =
            serde_json::from_value(json!({"host": "server1", "pattern": "user:*"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = RedisKeysTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }

    // ============== Stored credential stays on the local server ==============

    fn test_host_config() -> crate::config::HostConfig {
        server1_hosts().remove("server1").expect("server1")
    }

    /// Arguments of a valid call, with `extra` merged in.
    fn args_with(extra: &serde_json::Value) -> serde_json::Value {
        let mut value = json!({"host": "server1"});
        if let (Some(map), Some(more)) = (value.as_object_mut(), extra.as_object()) {
            map.extend(more.clone());
        }
        value
    }

    fn command_for(extra: &serde_json::Value) -> String {
        let host_config = test_host_config();
        let args: SshRedisKeysArgs = serde_json::from_value(args_with(extra)).expect("deserialize");
        RedisKeysTool::validate(&args, &host_config).unwrap_or_else(|e| panic!("{extra}: {e:?}"));
        RedisKeysTool::build_command(&args, &host_config).unwrap()
    }

    #[test]
    fn test_other_server_without_password_unsets_the_ambient_credential() {
        for host in ["redis.example.com", "10.0.0.5", "127.1"] {
            let cmd = command_for(&json!({"redis_host": host}));
            assert!(
                cmd.starts_with(&format!(
                    "unset REDISCLI_AUTH VALKEYCLI_AUTH && redis-cli -h '{host}'"
                )),
                "{cmd}"
            );
            assert!(!cmd.contains("--askpass"), "{cmd}");
        }
    }

    #[test]
    fn test_local_server_keeps_the_ambient_credential() {
        for extra in [
            json!({}),
            json!({"redis_host": "localhost"}),
            json!({"redis_host": "LOCALHOST"}),
            json!({"redis_host": "127.0.0.1"}),
            json!({"redis_host": "::1"}),
            json!({"redis_host": "::ffff:127.0.0.1"}),
        ] {
            let cmd = command_for(&extra);
            assert!(cmd.starts_with("redis-cli"), "{extra}: {cmd}");
            assert!(!cmd.contains("unset"), "{extra}: {cmd}");
        }
    }

    #[test]
    fn test_password_goes_through_askpass_never_argv() {
        for extra in [
            json!({"redis_password": "s3cret"}),
            json!({"redis_host": "localhost", "redis_password": "s3cret"}),
            json!({"redis_host": "redis.example.com", "redis_password": "s3cret"}),
        ] {
            let cmd = command_for(&extra);
            assert!(
                cmd.contains("printf '%s\\n' 's3cret' | redis-cli --askpass"),
                "{extra}: {cmd}"
            );
            assert!(!cmd.contains(" -a "), "{extra}: {cmd}");
            assert_eq!(
                cmd.starts_with("unset REDISCLI_AUTH VALKEYCLI_AUTH && "),
                extra.get("redis_host") == Some(&json!("redis.example.com")),
                "{extra}: {cmd}"
            );
        }
    }

    #[tokio::test]
    async fn test_refuses_a_bad_redis_password() {
        let handler = SshRedisKeysHandler::new();
        let ctx = permissive_ctx(mock_output(""));
        let too_long = "p".repeat(1025);
        for password in ["", "a\nb", "a\rb", "a\0b", too_long.as_str()] {
            let extra = json!({"redis_host": "redis.example.com", "redis_password": password});
            let result = handler.execute(Some(args_with(&extra)), &ctx).await;
            match result.unwrap_err() {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains("'redis_password'"), "{reason}");
                }
                e => panic!("Expected CommandDenied for {extra}, got: {e:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_refuses_a_malformed_redis_host() {
        let handler = SshRedisKeysHandler::new();
        let ctx = permissive_ctx(mock_output(""));
        let too_long = "a".repeat(254);
        for redis_host in ["", "-x", "a b", "a,b", "é", "a;b", too_long.as_str()] {
            let extra = json!({"redis_host": redis_host});
            let result = handler.execute(Some(args_with(&extra)), &ctx).await;
            match result.unwrap_err() {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains("'redis_host'"), "{redis_host:?}: {reason}");
                }
                e => panic!("Expected CommandDenied for {redis_host:?}, got: {e:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_other_server_with_password_runs() {
        let handler = SshRedisKeysHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let extra = json!({"redis_host": "redis.example.com", "redis_password": "s3cret"});
        let result = handler
            .execute(Some(args_with(&extra)), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
