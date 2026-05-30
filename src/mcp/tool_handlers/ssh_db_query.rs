//! SSH Database Query Tool Handler
//!
//! Executes SQL queries on remote databases via SSH.
//! Supports `MySQL` and `PostgreSQL` using their respective CLI clients.

use serde::Deserialize;

use crate::config::{HostConfig, RedactedSecret};
use crate::domain::{DatabaseCommandBuilder, DatabaseType};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshDbQueryArgs {
    host: String,
    db_type: String,
    query: String,
    database: String,
    #[serde(default)]
    db_host: Option<String>,
    #[serde(default)]
    db_port: Option<u16>,
    #[serde(default)]
    db_user: Option<String>,
    /// DB password from MCP JSON-RPC request body. Wrapped in
    /// `RedactedSecret` (FIND-029, F1-equivalent): the heap allocation is
    /// wiped on drop and `Debug`/`Display`/`Serialize` emit `[REDACTED]`,
    /// so the secret cannot leak through `format!("{args:?}")`. Production
    /// read sites pass it to the builder as `Option<&str>` via `as_deref()`
    /// (the single audited plaintext boundary, `Deref<Target = str>`).
    #[serde(default)]
    db_password: Option<RedactedSecret>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshDbQueryArgs);

#[mcp_standard_tool(name = "ssh_db_query", group = "database", annotation = "mutating")]
pub struct DbQueryTool;

impl StandardTool for DbQueryTool {
    type Args = SshDbQueryArgs;

    const NAME: &'static str = "ssh_db_query";

    const DESCRIPTION: &'static str = "Execute a SQL query on a remote database via SSH. Supports MySQL and PostgreSQL. The \
        query runs via the database CLI client (mysql/psql) on the remote host. Returns query \
        results as table or CSV text. Dangerous queries (DROP, TRUNCATE, DELETE FROM) are \
        blocked. Use ssh_db_dump for backups before destructive operations.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "db_type": {
                "type": "string",
                "enum": ["mysql", "postgresql"],
                "description": "Database type: mysql or postgresql"
            },
            "query": {
                "type": "string",
                "description": "SQL query to execute"
            },
            "database": {
                "type": "string",
                "description": "Database name"
            },
            "db_host": {
                "type": "string",
                "description": "Database host (default: localhost)"
            },
            "db_port": {
                "type": "integer",
                "description": "Database port (default: 3306 for MySQL, 5432 for PostgreSQL)"
            },
            "db_user": {
                "type": "string",
                "description": "Database user (default: root for MySQL, postgres for PostgreSQL)"
            },
            "db_password": {
                "type": "string",
                "description": "Database password"
            },
            "format": {
                "type": "string",
                "enum": ["table", "csv"],
                "description": "Output format (default: table)"
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
        "required": ["host", "db_type", "query", "database"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshDbQueryArgs, _host_config: &HostConfig) -> Result<String> {
        let db_type = DatabaseType::from_str_checked(&args.db_type)?;
        let db_host = args.db_host.as_deref().unwrap_or("localhost");
        let db_port = args.db_port.unwrap_or_else(|| db_type.default_port());
        let db_user = args
            .db_user
            .as_deref()
            .unwrap_or_else(|| db_type.default_user());
        Ok(DatabaseCommandBuilder::build_query_command(
            &db_type,
            db_host,
            db_port,
            db_user,
            args.db_password.as_deref(),
            &args.database,
            &args.query,
            args.format.as_deref(),
        ))
    }

    fn validate(args: &SshDbQueryArgs, _host_config: &HostConfig) -> Result<()> {
        DatabaseCommandBuilder::validate_query(&args.query)?;
        Ok(())
    }
}

/// Handler for the `ssh_db_query` tool.
pub type SshDbQueryHandler = StandardToolHandler<DbQueryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDbQueryHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_db_type() {
        let handler = SshDbQueryHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "db_type": "sqlite",
                    "query": "SELECT 1",
                    "database": "test"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::DatabaseCommand { reason } => {
                assert!(reason.contains("sqlite"));
            }
            e => panic!("Expected DatabaseCommand error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshDbQueryHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "db_type": "mysql",
                    "query": "SELECT 1",
                    "database": "test"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "nonexistent");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_dangerous_query_rejected() {
        let handler = SshDbQueryHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "db_type": "mysql",
                    "query": "DROP DATABASE production",
                    "database": "test"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("DROP DATABASE"));
            }
            e => panic!("Expected CommandDenied error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_dangerous_delete_query_rejected() {
        let handler = SshDbQueryHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "db_type": "postgresql",
                    "query": "DELETE FROM users WHERE id=1",
                    "database": "test"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("DELETE FROM"));
            }
            e => panic!("Expected CommandDenied error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshDbQueryHandler::new();
        assert_eq!(handler.name(), "ssh_db_query");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_db_query");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("db_type")));
        assert!(required.contains(&json!("query")));
        assert!(required.contains(&json!("database")));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDbQueryHandler::new();
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("db_host"));
        assert!(properties.contains_key("db_port"));
        assert!(properties.contains_key("db_user"));
        assert!(properties.contains_key("db_password"));
        assert!(properties.contains_key("format"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "db_type": "mysql",
            "query": "SELECT * FROM users",
            "database": "mydb",
            "db_host": "dbhost",
            "db_port": 3307,
            "db_user": "admin",
            "db_password": "secret",
            "format": "csv",
            "timeout_seconds": 120,
            "max_output": 5000
        });

        let args: SshDbQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.db_type, "mysql");
        assert_eq!(args.query, "SELECT * FROM users");
        assert_eq!(args.database, "mydb");
        assert_eq!(args.db_host, Some("dbhost".to_string()));
        assert_eq!(args.db_port, Some(3307));
        assert_eq!(args.db_user, Some("admin".to_string()));
        assert_eq!(args.db_password.as_deref(), Some("secret"));
        assert_eq!(args.format, Some("csv".to_string()));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "db_type": "postgresql",
            "query": "SELECT 1",
            "database": "testdb"
        });

        let args: SshDbQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.db_type, "postgresql");
        assert!(args.db_host.is_none());
        assert!(args.db_port.is_none());
        assert!(args.db_user.is_none());
        assert!(args.db_password.is_none());
        assert!(args.format.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "test-host",
            "db_type": "mysql",
            "query": "SELECT 1",
            "database": "testdb"
        });

        let args: SshDbQueryArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDbQueryArgs"));
        assert!(debug_str.contains("test-host"));
    }

    /// FIND-029 (F1-equivalent): the `db_password` field must not leak its
    /// plaintext through `Debug`. `RedactedSecret`'s hand-written `Debug`
    /// emits `[REDACTED]`, so the secret value must be absent from the
    /// rendered struct.
    #[test]
    fn args_debug_does_not_leak_db_password() {
        let args = SshDbQueryArgs {
            host: "test-host".to_string(),
            db_type: "mysql".to_string(),
            query: "SELECT 1".to_string(),
            database: "testdb".to_string(),
            db_host: None,
            db_port: None,
            db_user: None,
            db_password: Some(RedactedSecret::from("s3cr3t-pw")),
            format: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let rendered = format!("{args:?}");
        assert!(
            !rendered.contains("s3cr3t-pw"),
            "db_password leaked in Debug: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDbQueryHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"host": 123, "db_type": "mysql", "query": "SELECT 1", "database": "test"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshDbQueryHandler::new();
        let ctx = create_test_context();

        // Missing query field
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "db_type": "mysql",
                    "database": "test"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    use crate::config::{HostKeyVerification, OsType};

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

    #[test]
    fn test_build_command_mysql_defaults() {
        let args = SshDbQueryArgs {
            host: "server1".to_string(),
            db_type: "mysql".to_string(),
            query: "SELECT 1".to_string(),
            database: "mydb".to_string(),
            db_host: None,
            db_port: None,
            db_user: None,
            db_password: None,
            format: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = DbQueryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("mysql"));
        assert!(cmd.contains("-h 'localhost'"));
        assert!(cmd.contains("-P 3306"));
        assert!(cmd.contains("-u 'root'"));
        assert!(cmd.contains("'mydb'"));
        assert!(cmd.contains("SELECT 1"));
    }

    #[test]
    fn test_build_command_postgres_with_password() {
        let args = SshDbQueryArgs {
            host: "server1".to_string(),
            db_type: "postgresql".to_string(),
            query: "SELECT * FROM users".to_string(),
            database: "testdb".to_string(),
            db_host: Some("dbhost".to_string()),
            db_port: Some(5433),
            db_user: Some("admin".to_string()),
            db_password: Some(RedactedSecret::from("secret")),
            format: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = DbQueryTool::build_command(&args, &test_host_config()).unwrap();
        // FIND-031: PGPASSWORD env replaced by PGPASSFILE pgpass-file.
        assert!(cmd.contains("PGPASSFILE=$TMPF"));
        assert!(!cmd.contains("PGPASSWORD="));
        assert!(cmd.contains("psql"));
        assert!(cmd.contains("-h 'dbhost'"));
        assert!(cmd.contains("-p 5433"));
        assert!(cmd.contains("-U 'admin'"));
        assert!(cmd.contains("-d 'testdb'"));
    }

    #[test]
    fn test_build_command_with_format() {
        let args = SshDbQueryArgs {
            host: "server1".to_string(),
            db_type: "mysql".to_string(),
            query: "SELECT 1".to_string(),
            database: "mydb".to_string(),
            db_host: None,
            db_port: None,
            db_user: None,
            db_password: None,
            format: Some("csv".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = DbQueryTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-B"));
    }

    /// Regression: FIND-029 (F1-equivalent). The `db_password` field MUST be
    /// a `RedactedSecret` so the heap allocation is wiped on drop AND the
    /// secret is structurally incapable of leaking through `Debug`.
    /// This test is load-bearing at the type level: only
    /// `Option<RedactedSecret>` compiles below.
    #[test]
    fn test_db_password_field_is_redacted_secret() {
        let args: SshDbQueryArgs = serde_json::from_value(json!({
            "host": "h",
            "db_type": "mysql",
            "query": "SELECT 1",
            "database": "d",
            "db_password": "secret",
        }))
        .expect("deserialize");

        // Audited plaintext boundary: `Option<RedactedSecret>::as_deref()`
        // yields `Option<&str>` directly via `Deref<Target = str>`.
        let pw: Option<&str> = args.db_password.as_deref();
        assert_eq!(pw, Some("secret"));
        // Final type-pinning assertion: this line only compiles when the
        // field is exactly `Option<RedactedSecret>`.
        let _typed: &Option<RedactedSecret> = &args.db_password;
    }

    #[test]
    fn test_build_command_error_invalid_type() {
        let args = SshDbQueryArgs {
            host: "server1".to_string(),
            db_type: "sqlite".to_string(),
            query: "SELECT 1".to_string(),
            database: "mydb".to_string(),
            db_host: None,
            db_port: None,
            db_user: None,
            db_password: None,
            format: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let result = DbQueryTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
