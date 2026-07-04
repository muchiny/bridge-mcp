//! Database Command Builder
//!
//! Builds CLI commands for executing SQL queries, database dumps,
//! and restores on remote hosts via SSH.
//!
//! Supports `MySQL` and `PostgreSQL` databases. Commands are constructed
//! as shell strings to be executed on the remote host through the
//! standard SSH execution pipeline.

use std::fmt::Write;
use std::sync::LazyLock;

use regex::Regex;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

/// Pre-compiled regexes for dangerous SQL pattern detection.
/// Compiled once on first use, avoiding per-query regex compilation overhead.
#[allow(clippy::unwrap_used)] // static regex literals, exercised by every SQL validation test
static DANGEROUS_SQL_PATTERNS: LazyLock<[(Regex, &str); 7]> = LazyLock::new(|| {
    [
        (
            Regex::new(r"(?i)\bDROP\s+DATABASE\b").unwrap(),
            "DROP DATABASE",
        ),
        (Regex::new(r"(?i)\bDROP\s+TABLE\b").unwrap(), "DROP TABLE"),
        (Regex::new(r"(?i)\bTRUNCATE\b").unwrap(), "TRUNCATE"),
        (Regex::new(r"(?i)\bDELETE\s+FROM\b").unwrap(), "DELETE FROM"),
        (
            Regex::new(r"(?i)\bALTER\s+TABLE\b.*\bDROP\b").unwrap(),
            "ALTER TABLE ... DROP",
        ),
        (Regex::new(r"(?i)\bGRANT\b").unwrap(), "GRANT"),
        (Regex::new(r"(?i)\bREVOKE\b").unwrap(), "REVOKE"),
    ]
});

/// Supported database types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
}

impl DatabaseType {
    /// Parse a database type from a string.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::DatabaseCommand` if the string is not a recognized database type.
    pub fn from_str_checked(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "mysql" => Ok(Self::MySQL),
            "postgresql" | "postgres" | "psql" => Ok(Self::PostgreSQL),
            other => Err(BridgeError::DatabaseCommand {
                reason: format!(
                    "Unsupported database type: '{other}'. Supported types: mysql, postgresql"
                ),
            }),
        }
    }

    /// Return the default port for this database type.
    #[must_use]
    pub const fn default_port(&self) -> u16 {
        match self {
            Self::MySQL => 3306,
            Self::PostgreSQL => 5432,
        }
    }

    /// Return the default user for this database type.
    #[must_use]
    pub const fn default_user(&self) -> &'static str {
        match self {
            Self::MySQL => "root",
            Self::PostgreSQL => "postgres",
        }
    }
}

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// FIND-031: write a tempfile-creation prelude that stores the DB password
/// in a 0600 file, registers a cleanup trap, and (for `MySQL`) writes the
/// `[client]` section. The remote DB CLI then reads the password from the
/// file instead of from environ/argv — `/proc/PID/environ` and `ps eww`
/// stay clean.
///
/// Layout:
/// - `mktemp` creates a unique path (atomic, race-free).
/// - `trap '...' EXIT` ensures the file is shredded/removed even on signal.
/// - `chmod 600` restricts access to the bridge user before writing the
///   password (prevents a TOCTOU window where another process reads the
///   default-mode file).
/// - `printf '...' '<pw>' > $TMPF` writes the file content. The password
///   is a `printf` format-arg, not a CLI flag value visible to other
///   processes' `ps`.
///
/// `shred -u` overwrites the inode before unlink (defense against forensic
/// recovery of swapped-out tempfile content). On BusyBox/Alpine where
/// `shred` is missing, the `|| rm -f` fallback still removes the file.
///
/// `password` is single-quote-escaped POSIX-style. `printf '%s\n' '<pw>'`
/// treats `%` and `\\` literally inside the single-quoted argument, so no
/// further escaping is required for those chars.
fn write_mysql_password_tempfile(cmd: &mut String, password: &str) {
    let escaped_pw = password.replace('\'', "'\\''");
    let _ = write!(
        cmd,
        "TMPF=$(mktemp) && \
         trap 'shred -u \"$TMPF\" 2>/dev/null || rm -f \"$TMPF\"' EXIT && \
         chmod 600 \"$TMPF\" && \
         printf '[client]\\npassword=%s\\n' '{escaped_pw}' > $TMPF && "
    );
}

/// FIND-031: `PostgreSQL` counterpart of [`write_mysql_password_tempfile`].
/// Writes a `~/.pgpass`-style line in the format
/// `host:port:database:user:password` (per `psql(1)` man page) and then
/// exports `PGPASSFILE=$TMPF` so `psql` / `pg_dump` pick it up.
///
/// The pgpass format permits `:` and `\\` in the password, but they must
/// be escaped with a backslash. We perform that escaping here in addition
/// to the single-quote escape for the `printf` format-arg.
fn write_pg_password_tempfile(
    cmd: &mut String,
    db_host: &str,
    db_port: u16,
    database: &str,
    db_user: &str,
    password: &str,
) {
    // pgpass-format escaping: \ and : must be backslash-escaped.
    let pgpass_pw = password.replace('\\', "\\\\").replace(':', "\\:");
    // POSIX single-quote escaping for the printf format-arg.
    let printf_pw = pgpass_pw.replace('\'', "'\\''");
    let printf_host = db_host.replace('\\', "\\\\").replace(':', "\\:");
    let printf_db = database.replace('\\', "\\\\").replace(':', "\\:");
    let printf_user = db_user.replace('\\', "\\\\").replace(':', "\\:");
    let _ = write!(
        cmd,
        "TMPF=$(mktemp) && \
         trap 'shred -u \"$TMPF\" 2>/dev/null || rm -f \"$TMPF\"' EXIT && \
         chmod 600 \"$TMPF\" && \
         printf '%s:%s:%s:%s:%s\\n' '{printf_host}' '{db_port}' '{printf_db}' '{printf_user}' '{printf_pw}' > $TMPF && \
         PGPASSFILE=$TMPF "
    );
}

/// Helper to write the compression suffix or plain redirect.
fn write_compression_suffix(cmd: &mut String, compress: Option<&str>, output_file: &str) {
    let escaped_file = shell_escape(output_file);
    match compress {
        Some("gzip") => {
            let _ = write!(cmd, " | gzip > {escaped_file}");
        }
        Some("bzip2") => {
            let _ = write!(cmd, " | bzip2 > {escaped_file}");
        }
        Some("xz") => {
            let _ = write!(cmd, " | xz > {escaped_file}");
        }
        _ => {
            let _ = write!(cmd, " > {escaped_file}");
        }
    }
}

/// Builds database CLI commands for remote execution.
pub struct DatabaseCommandBuilder;

impl DatabaseCommandBuilder {
    /// Build a SQL query command.
    ///
    /// **FIND-031 (Sprint 2 Task 21):** when a password is supplied, it is
    /// written to a 0600 tempfile (cleaned up by `trap ... EXIT`) and the
    /// DB CLI reads it from there:
    /// - `MySQL`: `--defaults-extra-file=$TMPF` (must be the *first* mysql arg).
    /// - `PostgreSQL`: `PGPASSFILE=$TMPF` env var with a `~/.pgpass`-format file.
    ///
    /// The previous shape used `MYSQL_PWD=...` / `PGPASSWORD=...` env vars,
    /// which were visible in `/proc/PID/environ` on the remote host for the
    /// lifetime of the DB process. The tempfile pattern keeps the password
    /// out of both argv and environ.
    ///
    /// Resulting shape (`MySQL` with password):
    /// ```text
    /// TMPF=$(mktemp) && trap '...' EXIT && chmod 600 "$TMPF" && \
    /// printf '[client]\npassword=%s\n' '<pw>' > $TMPF && \
    /// mysql --defaults-extra-file=$TMPF -h host -P 3306 -u user db -e 'query'
    /// ```
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_query_command(
        db_type: &DatabaseType,
        db_host: &str,
        db_port: u16,
        db_user: &str,
        db_password: Option<&str>,
        database: &str,
        query: &str,
        format: Option<&str>,
    ) -> String {
        let escaped_query = query.replace('\'', "'\\''");
        let escaped_host = shell_escape(db_host);
        let escaped_user = shell_escape(db_user);
        let escaped_db = shell_escape(database);
        let mut cmd = String::new();

        match db_type {
            DatabaseType::MySQL => {
                if let Some(password) = db_password {
                    write_mysql_password_tempfile(&mut cmd, password);
                    // --defaults-extra-file must be the FIRST mysql argument.
                    let _ = write!(
                        cmd,
                        "mysql --defaults-extra-file=$TMPF -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} -e '{escaped_query}'"
                    );
                } else {
                    let _ = write!(
                        cmd,
                        "mysql -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} -e '{escaped_query}'"
                    );
                }

                if let Some("csv") = format {
                    cmd.push_str(" -B");
                }
            }
            DatabaseType::PostgreSQL => {
                if let Some(password) = db_password {
                    write_pg_password_tempfile(
                        &mut cmd, db_host, db_port, database, db_user, password,
                    );
                }

                let _ = write!(
                    cmd,
                    "psql -h {escaped_host} -p {db_port} -U {escaped_user} -d {escaped_db} -c '{escaped_query}'"
                );

                if let Some("csv") = format {
                    cmd.push_str(" --csv");
                }
            }
        }

        cmd
    }

    /// Build a database dump command.
    ///
    /// **FIND-031:** uses the same tempfile pattern as
    /// [`Self::build_query_command`] to keep passwords out of argv/environ.
    ///
    /// - `MySQL`: `mysqldump --defaults-extra-file=$TMPF -h host ...`.
    /// - `PostgreSQL`: `PGPASSFILE=$TMPF pg_dump -h host ...`.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_dump_command(
        db_type: &DatabaseType,
        db_host: &str,
        db_port: u16,
        db_user: &str,
        db_password: Option<&str>,
        database: &str,
        tables: Option<&[String]>,
        compress: Option<&str>,
        output_file: &str,
    ) -> String {
        let escaped_host = shell_escape(db_host);
        let escaped_user = shell_escape(db_user);
        let escaped_db = shell_escape(database);
        let mut cmd = String::new();

        match db_type {
            DatabaseType::MySQL => {
                if let Some(password) = db_password {
                    write_mysql_password_tempfile(&mut cmd, password);
                    let _ = write!(
                        cmd,
                        "mysqldump --defaults-extra-file=$TMPF -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db}"
                    );
                } else {
                    let _ = write!(
                        cmd,
                        "mysqldump -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db}"
                    );
                }

                if let Some(table_list) = tables {
                    for table in table_list {
                        let _ = write!(cmd, " {}", shell_escape(table));
                    }
                }
            }
            DatabaseType::PostgreSQL => {
                if let Some(password) = db_password {
                    write_pg_password_tempfile(
                        &mut cmd, db_host, db_port, database, db_user, password,
                    );
                }

                let _ = write!(
                    cmd,
                    "pg_dump -h {escaped_host} -p {db_port} -U {escaped_user} {escaped_db}"
                );

                if let Some(table_list) = tables {
                    for table in table_list {
                        let _ = write!(cmd, " -t {}", shell_escape(table));
                    }
                }
            }
        }

        write_compression_suffix(&mut cmd, compress, output_file);

        cmd
    }

    /// Build a database restore command.
    ///
    /// **FIND-031:** uses the same tempfile pattern as
    /// [`Self::build_query_command`] to keep passwords out of argv/environ.
    ///
    /// - `MySQL`: `mysql --defaults-extra-file=$TMPF ... < input_file`.
    /// - `PostgreSQL`: `PGPASSFILE=$TMPF psql ... < input_file`.
    #[must_use]
    pub fn build_restore_command(
        db_type: &DatabaseType,
        db_host: &str,
        db_port: u16,
        db_user: &str,
        db_password: Option<&str>,
        database: &str,
        input_file: &str,
    ) -> String {
        let escaped_host = shell_escape(db_host);
        let escaped_user = shell_escape(db_user);
        let escaped_db = shell_escape(database);
        let escaped_file = shell_escape(input_file);
        let mut cmd = String::new();

        match db_type {
            DatabaseType::MySQL => {
                if let Some(password) = db_password {
                    write_mysql_password_tempfile(&mut cmd, password);
                    let _ = write!(
                        cmd,
                        "mysql --defaults-extra-file=$TMPF -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} < {escaped_file}"
                    );
                } else {
                    let _ = write!(
                        cmd,
                        "mysql -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} < {escaped_file}"
                    );
                }
            }
            DatabaseType::PostgreSQL => {
                if let Some(password) = db_password {
                    write_pg_password_tempfile(
                        &mut cmd, db_host, db_port, database, db_user, password,
                    );
                }

                let _ = write!(
                    cmd,
                    "psql -h {escaped_host} -p {db_port} -U {escaped_user} -d {escaped_db} < {escaped_file}"
                );
            }
        }

        cmd
    }

    /// Validate a SQL query for dangerous patterns.
    ///
    /// Rejects queries containing DROP DATABASE, DROP TABLE, TRUNCATE,
    /// DELETE FROM, ALTER TABLE ... DROP, GRANT, REVOKE.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the query matches a dangerous pattern.
    pub fn validate_query(query: &str) -> Result<()> {
        for (re, name) in DANGEROUS_SQL_PATTERNS.iter() {
            if re.is_match(query) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Dangerous SQL operation '{name}' is not allowed via ssh_db_query. \
                         Use a direct database client for destructive operations."
                    ),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== DatabaseType Tests ==============

    #[test]
    fn test_database_type_from_str_mysql() {
        let dt = DatabaseType::from_str_checked("mysql").unwrap();
        assert_eq!(dt, DatabaseType::MySQL);
    }

    #[test]
    fn test_database_type_from_str_postgresql() {
        let dt = DatabaseType::from_str_checked("postgresql").unwrap();
        assert_eq!(dt, DatabaseType::PostgreSQL);
    }

    #[test]
    fn test_database_type_from_str_postgres() {
        let dt = DatabaseType::from_str_checked("postgres").unwrap();
        assert_eq!(dt, DatabaseType::PostgreSQL);
    }

    #[test]
    fn test_database_type_from_str_psql() {
        let dt = DatabaseType::from_str_checked("psql").unwrap();
        assert_eq!(dt, DatabaseType::PostgreSQL);
    }

    #[test]
    fn test_database_type_from_str_case_insensitive() {
        assert_eq!(
            DatabaseType::from_str_checked("MySQL").unwrap(),
            DatabaseType::MySQL
        );
        assert_eq!(
            DatabaseType::from_str_checked("POSTGRESQL").unwrap(),
            DatabaseType::PostgreSQL
        );
    }

    #[test]
    fn test_database_type_from_str_invalid() {
        let result = DatabaseType::from_str_checked("sqlite");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::DatabaseCommand { reason } => {
                assert!(reason.contains("sqlite"));
            }
            e => panic!("Expected DatabaseCommand error, got: {e:?}"),
        }
    }

    #[test]
    fn test_database_type_default_port() {
        assert_eq!(DatabaseType::MySQL.default_port(), 3306);
        assert_eq!(DatabaseType::PostgreSQL.default_port(), 5432);
    }

    #[test]
    fn test_database_type_default_user() {
        assert_eq!(DatabaseType::MySQL.default_user(), "root");
        assert_eq!(DatabaseType::PostgreSQL.default_user(), "postgres");
    }

    #[test]
    fn test_database_type_debug() {
        let dt = DatabaseType::MySQL;
        let debug = format!("{dt:?}");
        assert!(debug.contains("MySQL"));
    }

    #[test]
    fn test_database_type_clone() {
        let dt = DatabaseType::PostgreSQL;
        let cloned = dt.clone();
        assert_eq!(dt, cloned);
    }

    // ============== build_query_command Tests (MySQL) ==============

    #[test]
    fn test_build_query_mysql_all_options() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "dbhost",
            3306,
            "admin",
            Some("secret"),
            "mydb",
            "SELECT * FROM users",
            Some("csv"),
        );
        // FIND-031: password lives in a 0600 tempfile, mysql reads it via
        // --defaults-extra-file. No env var prefix anymore.
        assert!(cmd.starts_with("TMPF=$(mktemp)"));
        assert!(cmd.contains("printf '[client]\\npassword=%s\\n' 'secret'"));
        assert!(cmd.contains("mysql --defaults-extra-file=$TMPF"));
        assert!(cmd.contains("-h 'dbhost' -P 3306 -u 'admin' 'mydb'"));
        assert!(cmd.contains("-e 'SELECT * FROM users'"));
        assert!(cmd.contains("-B"));
    }

    #[test]
    fn test_build_query_mysql_no_password() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "testdb",
            "SELECT 1",
            None,
        );
        assert!(!cmd.contains("MYSQL_PWD"));
        assert!(cmd.starts_with("mysql -h 'localhost'"));
        assert!(cmd.contains("-e 'SELECT 1'"));
    }

    #[test]
    fn test_build_query_mysql_table_format() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "testdb",
            "SELECT 1",
            Some("table"),
        );
        assert!(!cmd.contains("-B"));
    }

    #[test]
    fn test_build_query_mysql_json_format() {
        // JSON not natively supported, should use default (no extra flag)
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "testdb",
            "SELECT 1",
            Some("json"),
        );
        assert!(!cmd.contains("-B"));
    }

    // ============== build_query_command Tests (PostgreSQL) ==============

    #[test]
    fn test_build_query_postgresql_all_options() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "pghost",
            5432,
            "pguser",
            Some("pgpass"),
            "pgdb",
            "SELECT * FROM orders",
            Some("csv"),
        );
        // FIND-031: password lives in a 0600 ~/.pgpass-format tempfile;
        // PGPASSFILE env var points psql at it. No PGPASSWORD anymore.
        assert!(cmd.starts_with("TMPF=$(mktemp)"));
        assert!(cmd.contains("PGPASSFILE=$TMPF"));
        // pgpass format: host:port:database:user:password
        assert!(
            cmd.contains("printf '%s:%s:%s:%s:%s\\n' 'pghost' '5432' 'pgdb' 'pguser' 'pgpass'")
        );
        assert!(cmd.contains("psql -h 'pghost' -p 5432 -U 'pguser' -d 'pgdb'"));
        assert!(cmd.contains("-c 'SELECT * FROM orders'"));
        assert!(cmd.contains("--csv"));
    }

    #[test]
    fn test_build_query_postgresql_no_password() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            None,
            "testdb",
            "SELECT 1",
            None,
        );
        assert!(!cmd.contains("PGPASSWORD"));
        assert!(cmd.starts_with("psql -h 'localhost'"));
    }

    #[test]
    fn test_build_query_postgresql_table_format() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            None,
            "testdb",
            "SELECT 1",
            Some("table"),
        );
        assert!(!cmd.contains("--csv"));
    }

    // ============== build_query_command with special characters ==============

    #[test]
    fn test_build_query_escapes_single_quotes_in_query() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "testdb",
            "SELECT * FROM users WHERE name = 'O'Brien'",
            None,
        );
        assert!(cmd.contains("O'\\''Brien"));
    }

    #[test]
    fn test_build_query_escapes_single_quotes_in_password() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            Some("pass'word"),
            "testdb",
            "SELECT 1",
            None,
        );
        // FIND-031: password is in a printf format-arg, not an env var.
        // Single-quote escape (POSIX `'\''` sequence) still applies.
        assert!(cmd.contains("'pass'\\''word'"));
        assert!(!cmd.contains("MYSQL_PWD"));
    }

    // ============== build_dump_command Tests ==============

    #[test]
    fn test_build_dump_mysql_basic() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            Some("pass"),
            "mydb",
            None,
            None,
            "/tmp/dump.sql",
        );
        // FIND-031: --defaults-extra-file pattern, no MYSQL_PWD env.
        assert!(cmd.contains("printf '[client]\\npassword=%s\\n' 'pass'"));
        assert!(cmd.contains("mysqldump --defaults-extra-file=$TMPF"));
        assert!(cmd.contains("-h 'localhost' -P 3306 -u 'root' 'mydb'"));
        assert!(cmd.contains("> '/tmp/dump.sql'"));
        assert!(!cmd.contains("| gzip"));
    }

    #[test]
    fn test_build_dump_mysql_with_tables() {
        let tables = vec!["users".to_string(), "orders".to_string()];
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            Some(&tables),
            None,
            "/tmp/dump.sql",
        );
        assert!(cmd.contains("'mydb' 'users' 'orders'"));
    }

    #[test]
    fn test_build_dump_mysql_gzip() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            Some("gzip"),
            "/tmp/dump.sql.gz",
        );
        assert!(cmd.contains("| gzip > '/tmp/dump.sql.gz'"));
    }

    #[test]
    fn test_build_dump_mysql_bzip2() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            Some("bzip2"),
            "/tmp/dump.sql.bz2",
        );
        assert!(cmd.contains("| bzip2 > '/tmp/dump.sql.bz2'"));
    }

    #[test]
    fn test_build_dump_mysql_xz() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            Some("xz"),
            "/tmp/dump.sql.xz",
        );
        assert!(cmd.contains("| xz > '/tmp/dump.sql.xz'"));
    }

    #[test]
    fn test_build_dump_postgresql_basic() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            Some("pgpass"),
            "mydb",
            None,
            None,
            "/tmp/dump.sql",
        );
        // FIND-031: PGPASSFILE pgpass-file pattern, no PGPASSWORD env.
        assert!(cmd.contains("PGPASSFILE=$TMPF"));
        assert!(cmd.contains("printf '%s:%s:%s:%s:%s\\n'"));
        assert!(cmd.contains("pg_dump -h 'localhost' -p 5432 -U 'postgres' 'mydb'"));
        assert!(cmd.contains("> '/tmp/dump.sql'"));
    }

    #[test]
    fn test_build_dump_postgresql_with_tables() {
        let tables = vec!["users".to_string(), "orders".to_string()];
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            None,
            "mydb",
            Some(&tables),
            None,
            "/tmp/dump.sql",
        );
        assert!(cmd.contains("-t 'users'"));
        assert!(cmd.contains("-t 'orders'"));
    }

    #[test]
    fn test_build_dump_postgresql_gzip() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            None,
            "mydb",
            None,
            Some("gzip"),
            "/tmp/dump.sql.gz",
        );
        assert!(cmd.contains("| gzip > '/tmp/dump.sql.gz'"));
    }

    #[test]
    fn test_build_dump_no_password() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            None,
            "/tmp/dump.sql",
        );
        assert!(!cmd.contains("MYSQL_PWD"));
    }

    // ============== build_restore_command Tests ==============

    #[test]
    fn test_build_restore_mysql() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            Some("pass"),
            "mydb",
            "/tmp/dump.sql",
        );
        // FIND-031: --defaults-extra-file pattern, no MYSQL_PWD env.
        assert!(cmd.contains("printf '[client]\\npassword=%s\\n' 'pass'"));
        assert!(cmd.contains(
            "mysql --defaults-extra-file=$TMPF -h 'localhost' -P 3306 -u 'root' 'mydb' < '/tmp/dump.sql'"
        ));
    }

    #[test]
    fn test_build_restore_postgresql() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            Some("pgpass"),
            "mydb",
            "/tmp/dump.sql",
        );
        // FIND-031: PGPASSFILE pgpass-file pattern, no PGPASSWORD env.
        assert!(cmd.contains("PGPASSFILE=$TMPF"));
        assert!(cmd.contains("printf '%s:%s:%s:%s:%s\\n'"));
        assert!(
            cmd.contains("psql -h 'localhost' -p 5432 -U 'postgres' -d 'mydb' < '/tmp/dump.sql'")
        );
    }

    #[test]
    fn test_build_restore_no_password() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            "/tmp/dump.sql",
        );
        assert!(!cmd.contains("MYSQL_PWD"));
        assert!(cmd.starts_with("mysql"));
    }

    // ============== Security: Injection Prevention Tests ==============

    #[test]
    fn test_build_query_host_injection_prevented() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "localhost && whoami > /tmp/pwned",
            3306,
            "root",
            None,
            "testdb",
            "SELECT 1",
            None,
        );
        // The malicious host should be wrapped in single quotes, neutralizing the injection
        assert!(cmd.contains("-h 'localhost && whoami > /tmp/pwned'"));
        assert!(!cmd.contains("-h localhost && whoami"));
    }

    #[test]
    fn test_build_dump_table_injection_prevented() {
        let tables = vec!["users; rm -rf /".to_string()];
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            Some(&tables),
            None,
            "/tmp/dump.sql",
        );
        // Table name should be escaped, not interpreted as a command
        assert!(cmd.contains("'users; rm -rf /'"));
        assert!(!cmd.contains("mydb users; rm -rf /"));
    }

    #[test]
    fn test_build_dump_output_file_injection_prevented() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            None,
            None,
            "/tmp/dump.sql; cat /etc/passwd",
        );
        // output_file should be escaped
        assert!(cmd.contains("> '/tmp/dump.sql; cat /etc/passwd'"));
    }

    #[test]
    fn test_build_restore_input_file_injection_prevented() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::MySQL,
            "localhost",
            3306,
            "root",
            None,
            "mydb",
            "/tmp/dump.sql; cat /etc/shadow",
        );
        assert!(cmd.contains("< '/tmp/dump.sql; cat /etc/shadow'"));
    }

    // ============== validate_query Tests ==============

    #[test]
    fn test_validate_query_safe_select() {
        assert!(DatabaseCommandBuilder::validate_query("SELECT * FROM users").is_ok());
    }

    #[test]
    fn test_validate_query_safe_insert() {
        assert!(
            DatabaseCommandBuilder::validate_query("INSERT INTO logs (msg) VALUES ('test')")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_query_safe_update() {
        assert!(
            DatabaseCommandBuilder::validate_query("UPDATE users SET name='test' WHERE id=1")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_query_drop_database() {
        let result = DatabaseCommandBuilder::validate_query("DROP DATABASE mydb");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("DROP DATABASE"));
            }
            e => panic!("Expected CommandDenied error, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_query_drop_table() {
        let result = DatabaseCommandBuilder::validate_query("DROP TABLE users");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_truncate() {
        let result = DatabaseCommandBuilder::validate_query("TRUNCATE TABLE users");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_delete_from() {
        let result = DatabaseCommandBuilder::validate_query("DELETE FROM users WHERE id=1");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_alter_drop() {
        let result = DatabaseCommandBuilder::validate_query("ALTER TABLE users DROP COLUMN email");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_grant() {
        let result =
            DatabaseCommandBuilder::validate_query("GRANT ALL PRIVILEGES ON mydb.* TO 'user'@'%'");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_revoke() {
        let result =
            DatabaseCommandBuilder::validate_query("REVOKE ALL PRIVILEGES ON mydb.* FROM 'user'");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_case_insensitive() {
        assert!(DatabaseCommandBuilder::validate_query("drop database mydb").is_err());
        assert!(DatabaseCommandBuilder::validate_query("Drop Table users").is_err());
        assert!(DatabaseCommandBuilder::validate_query("TRUNCATE table users").is_err());
        assert!(DatabaseCommandBuilder::validate_query("delete from users").is_err());
        assert!(DatabaseCommandBuilder::validate_query("grant all on mydb").is_err());
        assert!(DatabaseCommandBuilder::validate_query("revoke all on mydb").is_err());
    }

    #[test]
    fn test_validate_query_mixed_case() {
        assert!(DatabaseCommandBuilder::validate_query("dRoP dAtAbAsE mydb").is_err());
    }

    #[test]
    fn test_validate_query_alter_without_drop_is_ok() {
        assert!(
            DatabaseCommandBuilder::validate_query("ALTER TABLE users ADD COLUMN age INT").is_ok()
        );
    }

    #[test]
    fn test_validate_query_show_tables_is_ok() {
        assert!(DatabaseCommandBuilder::validate_query("SHOW TABLES").is_ok());
    }

    #[test]
    fn test_validate_query_describe_is_ok() {
        assert!(DatabaseCommandBuilder::validate_query("DESCRIBE users").is_ok());
    }

    #[test]
    fn test_validate_query_explain_is_ok() {
        assert!(DatabaseCommandBuilder::validate_query("EXPLAIN SELECT * FROM users").is_ok());
    }

    // ============== FIND-031: argv/environ leak prevention ==============

    /// FIND-031: `MySQL` password must NOT appear as `MYSQL_PWD=...` (visible
    /// in `/proc/PID/environ`) and must NOT appear in argv. The defaults-
    /// extra-file pattern stores the password in a 0600 tempfile, cleaned
    /// up by `trap ... EXIT`.
    ///
    /// Test strategy: split on `> $TMPF`, take the portion AFTER (which is
    /// the actual `mysql ...` invocation). Password may appear in the
    /// printf format-arg before the redirect (tempfile write, not argv)
    /// but must not appear after — that's the visible-to-`ps` portion.
    #[test]
    fn db_query_mysql_excludes_password_from_argv_and_environ() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "host",
            3306,
            "user",
            Some("topsecret"),
            "db",
            "select 1",
            None,
        );

        let argv = post_redirect(&cmd);
        assert!(
            !argv.contains("topsecret"),
            "FIND-031: password leaked into argv after tempfile write: {cmd}"
        );
        assert!(
            !cmd.contains("MYSQL_PWD="),
            "FIND-031: MYSQL_PWD env var must be replaced by --defaults-extra-file: {cmd}"
        );
        assert!(
            cmd.contains("--defaults-extra-file"),
            "FIND-031: must use --defaults-extra-file: {cmd}"
        );
    }

    /// FIND-031: `PostgreSQL` password must NOT appear as `PGPASSWORD=...`.
    /// Use `PGPASSFILE=$TMPF` with a 0600 pgpass file instead.
    #[test]
    fn db_query_pg_excludes_password_from_argv_and_environ() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "host",
            5432,
            "user",
            Some("topsecret"),
            "db",
            "select 1",
            None,
        );

        let argv = post_redirect(&cmd);
        assert!(
            !argv.contains("topsecret"),
            "FIND-031: password leaked into argv after tempfile write: {cmd}"
        );
        assert!(
            !cmd.contains("PGPASSWORD="),
            "FIND-031: PGPASSWORD env var must be replaced by PGPASSFILE: {cmd}"
        );
        assert!(
            cmd.contains("PGPASSFILE="),
            "FIND-031: must use PGPASSFILE: {cmd}"
        );
    }

    /// FIND-031: same protection on `mysqldump`.
    #[test]
    fn db_dump_mysql_excludes_password_from_argv_and_environ() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::MySQL,
            "host",
            3306,
            "user",
            Some("topsecret"),
            "db",
            None,
            None,
            "/tmp/out.sql",
        );

        let argv = post_redirect(&cmd);
        assert!(!argv.contains("topsecret"), "argv: {argv}");
        assert!(!cmd.contains("MYSQL_PWD="));
        assert!(cmd.contains("--defaults-extra-file"));
    }

    /// FIND-031: same protection on `pg_dump`.
    #[test]
    fn db_dump_pg_excludes_password_from_argv_and_environ() {
        let cmd = DatabaseCommandBuilder::build_dump_command(
            &DatabaseType::PostgreSQL,
            "host",
            5432,
            "user",
            Some("topsecret"),
            "db",
            None,
            None,
            "/tmp/out.sql",
        );

        let argv = post_redirect(&cmd);
        assert!(!argv.contains("topsecret"), "argv: {argv}");
        assert!(!cmd.contains("PGPASSWORD="));
        assert!(cmd.contains("PGPASSFILE="));
    }

    /// FIND-031: same protection on `mysql < dump.sql` restore path.
    #[test]
    fn db_restore_mysql_excludes_password_from_argv_and_environ() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::MySQL,
            "host",
            3306,
            "user",
            Some("topsecret"),
            "db",
            "/tmp/in.sql",
        );

        let argv = post_redirect(&cmd);
        assert!(!argv.contains("topsecret"), "argv: {argv}");
        assert!(!cmd.contains("MYSQL_PWD="));
        assert!(cmd.contains("--defaults-extra-file"));
    }

    /// FIND-031: same protection on `psql < dump.sql` restore path.
    #[test]
    fn db_restore_pg_excludes_password_from_argv_and_environ() {
        let cmd = DatabaseCommandBuilder::build_restore_command(
            &DatabaseType::PostgreSQL,
            "host",
            5432,
            "user",
            Some("topsecret"),
            "db",
            "/tmp/in.sql",
        );

        let argv = post_redirect(&cmd);
        assert!(!argv.contains("topsecret"), "argv: {argv}");
        assert!(!cmd.contains("PGPASSWORD="));
        assert!(cmd.contains("PGPASSFILE="));
    }

    /// Helper: returns the portion of the command AFTER the `> $TMPF` redirect.
    /// This is the `mysql ... ` / `psql ... ` invocation that is visible to
    /// `ps eww` on the remote host. The password must never appear here.
    /// If no tempfile redirect exists (no-password path), returns the whole
    /// command (the entire thing is argv).
    fn post_redirect(cmd: &str) -> &str {
        cmd.split_once("> $TMPF && ")
            .map_or(cmd, |(_, after)| after)
    }

    /// FIND-031: tempfile must be created with mode 0600 and cleaned up by
    /// trap-on-EXIT (with shred preferred, rm fallback).
    #[test]
    fn db_query_tempfile_is_secure_and_cleaned_up() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::MySQL,
            "host",
            3306,
            "user",
            Some("pw"),
            "db",
            "select 1",
            None,
        );
        assert!(cmd.contains("mktemp"), "must use mktemp: {cmd}");
        assert!(cmd.contains("chmod 600"), "must chmod 600: {cmd}");
        assert!(cmd.contains("trap"), "must register cleanup trap: {cmd}");
        assert!(
            cmd.contains("shred -u") || cmd.contains("rm -f"),
            "must clean up tempfile: {cmd}"
        );
    }
}
