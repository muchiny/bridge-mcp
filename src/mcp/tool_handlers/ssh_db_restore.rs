//! SSH Database Restore Tool Handler
//!
//! Restores databases from dump files on remote hosts via SSH.
//! Supports `MySQL` and `PostgreSQL`.

use serde::Deserialize;

use crate::config::{HostConfig, RedactedSecret};
use crate::domain::{DatabaseCommandBuilder, DatabaseType};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshDbRestoreArgs {
    host: String,
    db_type: String,
    database: String,
    input_file: String,
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
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshDbRestoreArgs);

#[mcp_standard_tool(name = "ssh_db_restore", group = "database", annotation = "mutating")]
pub struct DbRestoreTool;

impl StandardTool for DbRestoreTool {
    type Args = SshDbRestoreArgs;

    const NAME: &'static str = "ssh_db_restore";

    const DESCRIPTION: &'static str = "Restore a database from a dump file on a remote host via SSH. Supports MySQL and \
        PostgreSQL. The input_file must exist on the remote host (use ssh_upload to send it \
        first). Auto-detects compressed files (.gz, .bz2, .xz). Use ssh_db_dump to create \
        backups before restoring.";

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
                "description": "Database name to restore into"
            },
            "input_file": {
                "type": "string",
                "description": "Remote path to the dump file"
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
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["host", "db_type", "database", "input_file"]
    }"#;

    fn build_command(args: &SshDbRestoreArgs, _host_config: &HostConfig) -> Result<String> {
        let db_type = DatabaseType::from_str_checked(&args.db_type)?;
        let db_host = args.db_host.as_deref().unwrap_or("localhost");
        let db_port = args.db_port.unwrap_or_else(|| db_type.default_port());
        let db_user = args
            .db_user
            .as_deref()
            .unwrap_or_else(|| db_type.default_user());
        Ok(DatabaseCommandBuilder::build_restore_command(
            &db_type,
            db_host,
            db_port,
            db_user,
            args.db_password.as_deref(),
            &args.database,
            &args.input_file,
        ))
    }
}

/// Handler for the `ssh_db_restore` tool.
pub type SshDbRestoreHandler = StandardToolHandler<DbRestoreTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDbRestoreHandler::new();
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
        let handler = SshDbRestoreHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "db_type": "mongodb",
                    "database": "test",
                    "input_file": "/tmp/dump.sql"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::DatabaseCommand { reason } => {
                assert!(reason.contains("mongodb"));
            }
            e => panic!("Expected DatabaseCommand error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshDbRestoreHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "db_type": "mysql",
                    "database": "test",
                    "input_file": "/tmp/dump.sql"
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
        let handler = SshDbRestoreHandler::new();
        assert_eq!(handler.name(), "ssh_db_restore");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_db_restore");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("db_type")));
        assert!(required.contains(&json!("database")));
        assert!(required.contains(&json!("input_file")));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDbRestoreHandler::new();
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("db_host"));
        assert!(properties.contains_key("db_port"));
        assert!(properties.contains_key("db_user"));
        assert!(properties.contains_key("db_password"));
        assert!(properties.contains_key("timeout_seconds"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "db_type": "mysql",
            "database": "mydb",
            "input_file": "/tmp/dump.sql",
            "db_host": "dbhost",
            "db_port": 3307,
            "db_user": "admin",
            "db_password": "secret",
            "timeout_seconds": 600
        });

        let args: SshDbRestoreArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.db_type, "mysql");
        assert_eq!(args.database, "mydb");
        assert_eq!(args.input_file, "/tmp/dump.sql");
        assert_eq!(args.db_host, Some("dbhost".to_string()));
        assert_eq!(args.db_port, Some(3307));
        assert_eq!(args.db_user, Some("admin".to_string()));
        assert_eq!(args.db_password.as_deref(), Some("secret"));
        assert_eq!(args.timeout_seconds, Some(600));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "db_type": "postgresql",
            "database": "testdb",
            "input_file": "/tmp/dump.sql"
        });

        let args: SshDbRestoreArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.db_type, "postgresql");
        assert!(args.db_host.is_none());
        assert!(args.db_port.is_none());
        assert!(args.db_user.is_none());
        assert!(args.db_password.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "test-host",
            "db_type": "mysql",
            "database": "testdb",
            "input_file": "/tmp/dump.sql"
        });

        let args: SshDbRestoreArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDbRestoreArgs"));
        assert!(debug_str.contains("test-host"));
    }

    /// FIND-029 (F1-equivalent): the `db_password` field must not leak its
    /// plaintext through `Debug`.
    #[test]
    fn args_debug_does_not_leak_db_password() {
        let args: SshDbRestoreArgs = serde_json::from_value(json!({
            "host": "test-host",
            "db_type": "mysql",
            "database": "testdb",
            "input_file": "/tmp/dump.sql",
            "db_password": "s3cr3t-pw",
        }))
        .expect("deserialize");
        let rendered = format!("{args:?}");
        assert!(
            !rendered.contains("s3cr3t-pw"),
            "db_password leaked in Debug: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDbRestoreHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({"host": 123, "db_type": "mysql", "database": "test", "input_file": "/tmp/dump.sql"})),
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
        let handler = SshDbRestoreHandler::new();
        let ctx = create_test_context();

        // Missing input_file field
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

    /// Regression: FIND-029 (F1-equivalent). The `db_password` field MUST be
    /// a `RedactedSecret` so the heap allocation is wiped on drop AND the
    /// secret cannot leak through `Debug`. This test is load-bearing at the
    /// type level: only `Option<RedactedSecret>` compiles below.
    #[test]
    fn test_db_password_field_is_redacted_secret() {
        let args: SshDbRestoreArgs = serde_json::from_value(json!({
            "host": "h",
            "db_type": "postgresql",
            "database": "d",
            "input_file": "/tmp/dump.sql",
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
