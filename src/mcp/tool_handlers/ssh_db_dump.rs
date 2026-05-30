//! SSH Database Dump Tool Handler
//!
//! Creates database dumps on remote hosts via SSH.
//! Supports `MySQL` (`mysqldump`) and `PostgreSQL` (`pg_dump`).

use serde::Deserialize;

use crate::config::{HostConfig, RedactedSecret};
use crate::domain::{DatabaseCommandBuilder, DatabaseType};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshDbDumpArgs {
    host: String,
    db_type: String,
    database: String,
    output_file: String,
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
    tables: Option<Vec<String>>,
    #[serde(default)]
    compress: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshDbDumpArgs);

#[mcp_standard_tool(name = "ssh_db_dump", group = "database", annotation = "mutating")]
pub struct DbDumpTool;

impl StandardTool for DbDumpTool {
    type Args = SshDbDumpArgs;

    const NAME: &'static str = "ssh_db_dump";

    const DESCRIPTION: &'static str = "Create a database dump on a remote host via SSH. Uses mysqldump for MySQL and pg_dump \
        for PostgreSQL. The dump file is saved on the remote host at output_file. Supports \
        optional compression (gzip, bzip2, xz) and per-table dumps. Use ssh_download to \
        retrieve the dump file locally, or ssh_db_restore to restore it.";

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
            "database": {
                "type": "string",
                "description": "Database name to dump"
            },
            "output_file": {
                "type": "string",
                "description": "Remote path for the dump file"
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
            "tables": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Specific tables to dump (default: all tables)"
            },
            "compress": {
                "type": "string",
                "enum": ["gzip", "bzip2", "xz"],
                "description": "Compression method for the dump file"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["host", "db_type", "database", "output_file"]
    }"#;

    fn build_command(args: &SshDbDumpArgs, _host_config: &HostConfig) -> Result<String> {
        let db_type = DatabaseType::from_str_checked(&args.db_type)?;
        let db_host = args.db_host.as_deref().unwrap_or("localhost");
        let db_port = args.db_port.unwrap_or_else(|| db_type.default_port());
        let db_user = args
            .db_user
            .as_deref()
            .unwrap_or_else(|| db_type.default_user());
        Ok(DatabaseCommandBuilder::build_dump_command(
            &db_type,
            db_host,
            db_port,
            db_user,
            args.db_password.as_deref(),
            &args.database,
            args.tables.as_deref(),
            args.compress.as_deref(),
            &args.output_file,
        ))
    }
}

/// Handler for the `ssh_db_dump` tool.
pub type SshDbDumpHandler = StandardToolHandler<DbDumpTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDbDumpHandler::new();
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
        let handler = SshDbDumpHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "db_type": "oracle",
                    "database": "test",
                    "output_file": "/tmp/dump.sql"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::DatabaseCommand { reason } => {
                assert!(reason.contains("oracle"));
            }
            e => panic!("Expected DatabaseCommand error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshDbDumpHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "db_type": "mysql",
                    "database": "test",
                    "output_file": "/tmp/dump.sql"
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

    #[test]
    fn test_schema() {
        let handler = SshDbDumpHandler::new();
        assert_eq!(handler.name(), "ssh_db_dump");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_db_dump");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("db_type")));
        assert!(required.contains(&json!("database")));
        assert!(required.contains(&json!("output_file")));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDbDumpHandler::new();
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("db_host"));
        assert!(properties.contains_key("db_port"));
        assert!(properties.contains_key("db_user"));
        assert!(properties.contains_key("db_password"));
        assert!(properties.contains_key("tables"));
        assert!(properties.contains_key("compress"));
        assert!(properties.contains_key("timeout_seconds"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "db_type": "mysql",
            "database": "mydb",
            "output_file": "/tmp/dump.sql",
            "db_host": "dbhost",
            "db_port": 3307,
            "db_user": "admin",
            "db_password": "secret",
            "tables": ["users", "orders"],
            "compress": "gzip",
            "timeout_seconds": 300
        });

        let args: SshDbDumpArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.db_type, "mysql");
        assert_eq!(args.database, "mydb");
        assert_eq!(args.output_file, "/tmp/dump.sql");
        assert_eq!(args.db_host, Some("dbhost".to_string()));
        assert_eq!(args.db_port, Some(3307));
        assert_eq!(
            args.tables,
            Some(vec!["users".to_string(), "orders".to_string()])
        );
        assert_eq!(args.compress, Some("gzip".to_string()));
        assert_eq!(args.timeout_seconds, Some(300));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "db_type": "postgresql",
            "database": "testdb",
            "output_file": "/tmp/dump.sql"
        });

        let args: SshDbDumpArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.db_type, "postgresql");
        assert!(args.db_host.is_none());
        assert!(args.tables.is_none());
        assert!(args.compress.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "test-host",
            "db_type": "mysql",
            "database": "testdb",
            "output_file": "/tmp/dump.sql"
        });

        let args: SshDbDumpArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDbDumpArgs"));
        assert!(debug_str.contains("test-host"));
    }

    /// FIND-029 (F1-equivalent): the `db_password` field must not leak its
    /// plaintext through `Debug`.
    #[test]
    fn args_debug_does_not_leak_db_password() {
        let args = SshDbDumpArgs {
            host: "test-host".to_string(),
            db_type: "mysql".to_string(),
            database: "testdb".to_string(),
            output_file: "/tmp/dump.sql".to_string(),
            db_host: None,
            db_port: None,
            db_user: None,
            db_password: Some(RedactedSecret::from("s3cr3t-pw")),
            tables: None,
            compress: None,
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
        let handler = SshDbDumpHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({"host": 123, "db_type": "mysql", "database": "test", "output_file": "/tmp/dump.sql"})),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshDbDumpHandler::new();
        let ctx = create_test_context();

        // Missing output_file field
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
        let args = SshDbDumpArgs {
            host: "server1".to_string(),
            db_type: "mysql".to_string(),
            database: "mydb".to_string(),
            output_file: "/tmp/dump.sql".to_string(),
            db_host: None,
            db_port: None,
            db_user: None,
            db_password: None,
            tables: None,
            compress: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = DbDumpTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("mysqldump"));
        assert!(cmd.contains("-h 'localhost'"));
        assert!(cmd.contains("-P 3306"));
        assert!(cmd.contains("-u 'root'"));
        assert!(cmd.contains("'mydb'"));
        assert!(cmd.contains("> '/tmp/dump.sql'"));
    }

    #[test]
    fn test_build_command_with_tables_compress() {
        let args = SshDbDumpArgs {
            host: "server1".to_string(),
            db_type: "mysql".to_string(),
            database: "mydb".to_string(),
            output_file: "/tmp/dump.sql.gz".to_string(),
            db_host: None,
            db_port: None,
            db_user: None,
            db_password: None,
            tables: Some(vec!["users".to_string(), "orders".to_string()]),
            compress: Some("gzip".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = DbDumpTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("'users'"));
        assert!(cmd.contains("'orders'"));
        assert!(cmd.contains("| gzip >"));
    }

    #[test]
    fn test_build_command_postgres() {
        let args = SshDbDumpArgs {
            host: "server1".to_string(),
            db_type: "postgresql".to_string(),
            database: "testdb".to_string(),
            output_file: "/tmp/dump.sql".to_string(),
            db_host: None,
            db_port: None,
            db_user: None,
            db_password: None,
            tables: None,
            compress: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = DbDumpTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("pg_dump"));
        assert!(cmd.contains("-h 'localhost'"));
        assert!(cmd.contains("-p 5432"));
        assert!(cmd.contains("-U 'postgres'"));
        assert!(cmd.contains("'testdb'"));
    }

    #[test]
    fn test_build_command_all_opts() {
        let args = SshDbDumpArgs {
            host: "server1".to_string(),
            db_type: "postgresql".to_string(),
            database: "proddb".to_string(),
            output_file: "/tmp/dump.sql.xz".to_string(),
            db_host: Some("dbhost".to_string()),
            db_port: Some(5433),
            db_user: Some("admin".to_string()),
            db_password: Some(RedactedSecret::from("secret")),
            tables: Some(vec!["users".to_string()]),
            compress: Some("xz".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = DbDumpTool::build_command(&args, &test_host_config()).unwrap();
        // FIND-031: PGPASSWORD env replaced by PGPASSFILE pgpass-file.
        assert!(cmd.contains("PGPASSFILE=$TMPF"));
        assert!(!cmd.contains("PGPASSWORD="));
        assert!(cmd.contains("pg_dump"));
        assert!(cmd.contains("-h 'dbhost'"));
        assert!(cmd.contains("-p 5433"));
        assert!(cmd.contains("-U 'admin'"));
        assert!(cmd.contains("-t 'users'"));
        assert!(cmd.contains("| xz >"));
    }

    /// Regression: FIND-029 (F1-equivalent). The `db_password` field MUST be
    /// a `RedactedSecret` so the heap allocation is wiped on drop AND the
    /// secret cannot leak through `Debug`. This test is load-bearing at the
    /// type level: only `Option<RedactedSecret>` compiles below.
    #[test]
    fn test_db_password_field_is_redacted_secret() {
        let args: SshDbDumpArgs = serde_json::from_value(json!({
            "host": "h",
            "db_type": "mysql",
            "database": "d",
            "output_file": "/tmp/dump.sql",
            "db_password": "secret",
        }))
        .expect("deserialize");

        // Audited plaintext boundary: `Option<RedactedSecret>::as_deref()`
        // yields `Option<&str>` directly via `Deref<Target = str>`.
        let pw: Option<&str> = args.db_password.as_deref();
        assert_eq!(pw, Some("secret"));
        // Final type-pinning assertion: only compiles when the field is
        // exactly `Option<RedactedSecret>`.
        let _typed: &Option<RedactedSecret> = &args.db_password;
    }
}
