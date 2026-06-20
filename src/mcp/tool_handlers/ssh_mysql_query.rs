//! SSH `MySQL` Query Tool Handler
//!
//! Execute SQL queries on remote `MySQL` databases.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

use super::utils::shell_escape;

#[derive(Debug, Deserialize)]
pub struct SshMysqlQueryArgs {
    host: String,
    query: String,
    database: Option<String>,
    db_user: Option<String>,
    db_port: Option<u16>,
    format: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshMysqlQueryArgs);

#[mcp_standard_tool(name = "ssh_mysql_query", group = "mysql", annotation = "mutating")]
pub struct MysqlQueryTool;

impl StandardTool for MysqlQueryTool {
    type Args = SshMysqlQueryArgs;

    const NAME: &'static str = "ssh_mysql_query";

    const DESCRIPTION: &'static str = "Execute a SQL query on a remote MySQL database via the \
        mysql client. Returns query results in table, CSV, or JSON format. Accepts any SQL \
        statement including DDL (DROP, ALTER) and DML (INSERT, UPDATE, DELETE) — treat this \
        tool as potentially destructive. Auth is read from ~/.my.cnf on the remote host when \
        no db_user is supplied; for password-protected accounts, configure a [client] section \
        in ~/.my.cnf (password=...) on the remote host rather than passing credentials in \
        plaintext. Prefer this over ssh_exec for MySQL interactions. For a quick server \
        health check (version, databases, connection count) without writing SQL, use \
        ssh_mysql_status instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "query": {
                "type": "string",
                "description": "SQL query to execute"
            },
            "database": {
                "type": "string",
                "description": "Database name"
            },
            "db_user": {
                "type": "string",
                "description": "Database user (default: root)"
            },
            "db_port": {
                "type": "integer",
                "description": "Database port (default: 3306)",
                "minimum": 1,
                "maximum": 65535
            },
            "format": {
                "type": "string",
                "description": "Output format: table, csv, json (default: table)",
                "enum": ["table", "csv", "json"]
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
        "required": ["host", "query"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshMysqlQueryArgs, _host_config: &HostConfig) -> Result<String> {
        let user = args.db_user.as_deref().unwrap_or("root");
        let port = args.db_port.unwrap_or(3306);

        let format_flag = match args.format.as_deref() {
            Some("csv") => " -B",
            Some("json") => " --json",
            _ => "",
        };

        let db_part = match args.database.as_deref() {
            Some(db) => format!(" {}", shell_escape(db)),
            None => String::new(),
        };

        Ok(format!(
            "mysql -h localhost -P {port} -u {user}{db_part}{format_flag} -e {query}",
            port = port,
            user = shell_escape(user),
            db_part = db_part,
            format_flag = format_flag,
            query = shell_escape(&args.query),
        ))
    }
}

/// Handler for the `ssh_mysql_query` tool.
pub type SshMysqlQueryHandler = StandardToolHandler<MysqlQueryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshMysqlQueryHandler::new();
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
        let handler = SshMysqlQueryHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "query": "SELECT 1"})),
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
        let handler = SshMysqlQueryHandler::new();
        assert_eq!(handler.name(), "ssh_mysql_query");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_mysql_query");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("query")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "query": "SELECT * FROM users",
            "database": "mydb",
            "db_user": "admin",
            "db_port": 3307,
            "format": "csv",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/mysql_query.txt"
        });
        let args: SshMysqlQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.query, "SELECT * FROM users");
        assert_eq!(args.database.as_deref(), Some("mydb"));
        assert_eq!(args.db_user.as_deref(), Some("admin"));
        assert_eq!(args.db_port, Some(3307));
        assert_eq!(args.format.as_deref(), Some("csv"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/mysql_query.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "query": "SELECT 1"});
        let args: SshMysqlQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.query, "SELECT 1");
        assert!(args.database.is_none());
        assert!(args.db_user.is_none());
        assert!(args.db_port.is_none());
        assert!(args.format.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshMysqlQueryHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("database"));
        assert!(properties.contains_key("db_user"));
        assert!(properties.contains_key("db_port"));
        assert!(properties.contains_key("format"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "query": "SELECT 1"});
        let args: SshMysqlQueryArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshMysqlQueryArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshMysqlQueryHandler::new();
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
        let handler = SshMysqlQueryHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(
                Some(json!({"host": "server1", "query": "SELECT 1", "database": "testdb"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
