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

use super::shell::refuse_option_like;

/// `SQL` comments (block, `-- ` and `#` line): replaced by a space before the
/// deny list runs, so `DROP/**/TABLE t` is read as `DROP TABLE t`.
#[allow(clippy::unwrap_used)] // static regex literal, exercised by the comment tests
static SQL_COMMENTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/|--[^\n]*|#[^\n]*").unwrap());

/// Block-comment delimiters (`/*`, `/*!`, `/*M!` (`MariaDB`), `/*+`, a version
/// number after `/*!` or `/*M!`, and `*/`): replaced by a space with the comment text kept, so a
/// keyword hidden in an executable comment (`/*!DROP*/ TABLE t`) or split by a
/// nested `PostgreSQL` comment (`DROP /* /* */ */ TABLE t`) is read by the deny
/// list.
#[allow(clippy::unwrap_used)] // static regex literal, exercised by the comment tests
static SQL_COMMENT_DELIMITERS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/\*(?:M?!|\+)?[0-9]*|\*/").unwrap());

/// Words the `mysql` client runs as its own commands when they open a
/// statement or a line (`system` runs a shell, `pager` pipes the output into
/// one, `source`/`tee`/`ssl_session_data_print` read or write files, `connect`
/// reconnects to a host of the caller's choosing).
///
/// The harmless commands (`use`, `status`, `print`, `go`, `clear`, `help`,
/// `exit`, `quit`, `prompt`, `charset`, `warnings`, `rehash`, ...) are left out:
/// they are common column names or only change client state, and
/// `--binary-mode` disables the whole set anyway.
const MYSQL_CLIENT_WORDS: &[&str] = &[
    "system",
    "source",
    "tee",
    "pager",
    "edit",
    "delimiter",
    "connect",
    "ssl_session_data_print",
    "resetconnection",
    "query_attributes",
];

/// Pre-compiled regexes for dangerous SQL pattern detection.
/// Compiled once on first use, avoiding per-query regex compilation overhead.
#[allow(clippy::unwrap_used)] // static regex literals, exercised by every SQL validation test
static DANGEROUS_SQL_PATTERNS: LazyLock<[(Regex, &str); 8]> = LazyLock::new(|| {
    [
        (
            Regex::new(r"(?i)\bDROP\s+DATABASE\b").unwrap(),
            "DROP DATABASE",
        ),
        (Regex::new(r"(?i)\bDROP\s+SCHEMA\b").unwrap(), "DROP SCHEMA"),
        (Regex::new(r"(?i)\bDROP\s+TABLES?\b").unwrap(), "DROP TABLE"),
        (Regex::new(r"(?i)\bTRUNCATE\b").unwrap(), "TRUNCATE"),
        (
            Regex::new(r"(?i)\bDELETE\s+(?:(?:IGNORE|LOW_PRIORITY|QUICK)\s+)*FROM\b").unwrap(),
            "DELETE FROM",
        ),
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
///   is a `printf` format-arg, so it is never a flag of the `mysql` client
///   binary, and the tempfile is `chmod 600` and `shred -u`'d.
///
/// **Known gap, not protected:** the command string itself is the remote
/// shell's argv (`bash -c '<whole string>'`) for the duration of the call, so
/// the password is readable with `ps` on the target. And because `db_password`
/// arrives as a caller argument rather than from config, it is outside the
/// masker's exact-match value set, so whether it is masked in the audit trail
/// depends entirely on the entropy heuristic: masked when it is at least 23
/// bytes long (`2^4.5`: below that no token can reach 4.5 bits per character,
/// whatever `entropy_min_length` says) and above 4.5 bits per character, not
/// masked at all below either threshold. Fixing this is a separate task; the `exec_with_stdin` seam is not
/// directly reusable, since its one stdin is documented as carrying the sudo
/// password and nothing else.
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
    // pgpass-format escaping first, then the POSIX single-quote escape — the
    // three values are emitted as single-quoted `printf` arguments just like
    // the password, and a bare `'` used to close the quoting.
    let printf_host = db_host
        .replace('\\', "\\\\")
        .replace(':', "\\:")
        .replace('\'', "'\\''");
    let printf_db = database
        .replace('\\', "\\\\")
        .replace(':', "\\:")
        .replace('\'', "'\\''");
    let printf_user = db_user
        .replace('\\', "\\\\")
        .replace(':', "\\:")
        .replace('\'', "'\\''");
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
    /// The `MySQL` command carries `--binary-mode`: with `-e` the client is
    /// non-interactive, and that option turns off its command parser (`\!`,
    /// `system`, `source`, `tee`, `pager`, `edit`, `connect`, ...), so a query
    /// cannot make the client run a shell or touch a file whatever
    /// [`Self::validate_client_query`] missed. Only `\C` and `delimiter` stay.
    ///
    /// Resulting shape (`MySQL` with password):
    /// ```text
    /// TMPF=$(mktemp) && trap '...' EXIT && chmod 600 "$TMPF" && \
    /// printf '[client]\npassword=%s\n' '<pw>' > $TMPF && \
    /// mysql --defaults-extra-file=$TMPF -h host -P 3306 -u user db --binary-mode -e 'query'
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
                        "mysql --defaults-extra-file=$TMPF -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} --binary-mode -e '{escaped_query}'"
                    );
                } else {
                    let _ = write!(
                        cmd,
                        "mysql -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} --binary-mode -e '{escaped_query}'"
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
    /// - `MySQL`: `mysql --defaults-extra-file=$TMPF ... --binary-mode < input_file`.
    ///   `--binary-mode` switches the client's own commands (`\!`, `system`,
    ///   `source`, ...) off, so a `\! cmd` line in the file is not run in a
    ///   shell; `mysqldump` output does not depend on them.
    /// - `PostgreSQL`: `PGPASSFILE=$TMPF psql ... < input_file`. `psql` has no
    ///   option that turns its backslash commands off: the file is run as a
    ///   `psql` script, and a line starting with `\` (`\!`, `\copy`) acts on
    ///   the remote host.
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
                        "mysql --defaults-extra-file=$TMPF -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} --binary-mode < {escaped_file}"
                    );
                } else {
                    let _ = write!(
                        cmd,
                        "mysql -h {escaped_host} -P {db_port} -u {escaped_user} {escaped_db} --binary-mode < {escaped_file}"
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
    /// Rejects queries containing DROP DATABASE, DROP SCHEMA, DROP TABLE,
    /// TRUNCATE, DELETE FROM, ALTER TABLE ... DROP, GRANT, REVOKE. The query
    /// is checked as written, with its comments read as spaces, and with only
    /// the comment delimiters read as spaces (the text inside kept), so
    /// `DROP/**/TABLE t`, `DROP /* /* */ */ TABLE t` (`PostgreSQL` nests block
    /// comments) and `/*!DROP*/ TABLE t` (`MySQL` runs the inside of a `/*!`
    /// comment) and `/*M!100100DROP*/ TABLE t` (`MariaDB` runs the inside of a
    /// `/*M!` comment) do not slip through. A `/*!` or `/*M!` comment is refused
    /// outright.
    ///
    /// This is a best-effort guard against mistakes, not a security boundary:
    /// other statements (`UPDATE` without `WHERE`, `INTO OUTFILE`,
    /// `COPY ... TO PROGRAM`) are not inspected.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the query matches a dangerous pattern.
    pub fn validate_query(query: &str) -> Result<()> {
        if query.contains("/*!") || query.contains("/*M!") {
            return Err(BridgeError::CommandDenied {
                reason: "'query' must not contain a '/*!' or '/*M!' comment: MySQL and MariaDB \
                         execute its content, which the dangerous-statement check cannot see"
                    .to_string(),
            });
        }
        let uncommented = SQL_COMMENTS.replace_all(query, " ");
        let delimiters_only = SQL_COMMENT_DELIMITERS.replace_all(query, " ");
        for (re, name) in DANGEROUS_SQL_PATTERNS.iter() {
            if re.is_match(query) || re.is_match(&uncommented) || re.is_match(&delimiters_only) {
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

    /// Refuse a query the database client would run as one of its own
    /// commands instead of sending it to the server.
    ///
    /// The `mysql` client runs `\! cmd` and `system cmd` in a shell, and
    /// `source`, `tee`, `pager`, `edit`, `connect`, `ssl_session_data_print`
    /// read or write files, spawn programs or reconnect. `psql -c` runs a
    /// backslash command (`\! cmd`) when the string starts with a backslash.
    ///
    /// For `MySQL` the builders also pass `--binary-mode`, which switches the
    /// client's command parser off; this check is the second layer. The
    /// client's own lexer depends on the server's `sql_mode` and can change
    /// partway through a query, so it is not modelled exactly: a query is
    /// refused when a statement starts with a client command word (a statement
    /// starts at the beginning of the query or after a `;` outside quotes and
    /// comments, and leading whitespace and plain comments are skipped; a
    /// column called `source` at the start of a line is fine), when it has a
    /// backslash outside a quoted string (read both with and without backslash
    /// escapes), and, whenever it has a backslash at all, when it also has a
    /// backtick or more than one statement. A backslash inside a `'` or `"`
    /// string of a single statement (`LIKE '50\%'`) and inside a `-- ` or `#`
    /// comment is fine.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `query`.
    pub fn validate_client_query(db_type: &DatabaseType, query: &str) -> Result<()> {
        let found = match db_type {
            DatabaseType::PostgreSQL => query.trim_start().starts_with('\\'),
            DatabaseType::MySQL => mysql_has_client_command(query),
        };
        if found {
            return Err(BridgeError::CommandDenied {
                reason: "'query' must not contain a database client command (a backslash \
                         command such as \\!, or system/source/tee/pager/edit/delimiter/connect \
                         starting a statement): the client would run it on the remote host"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Refuse a `PostgreSQL` database name that `libpq` would read as a
    /// connection string.
    ///
    /// `psql -d`, `pg_dump` and `pg_restore` expand a database name holding
    /// `=` (`dbname=x host=10.0.0.66`) or starting with `postgres://` /
    /// `postgresql://` into connection parameters, which override `-h`/`-p`
    /// and send the stored password to a host of the caller's choosing.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `database`.
    pub fn validate_postgres_database(database: &str) -> Result<()> {
        let lower = database.trim_start().to_ascii_lowercase();
        if database.contains('=')
            || lower.starts_with("postgres://")
            || lower.starts_with("postgresql://")
        {
            return Err(BridgeError::CommandDenied {
                reason: "'database' must be a database name: a value with '=' or starting \
                         with postgres:// or postgresql:// is read as a connection string \
                         that can redirect the connection"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Validate the connection arguments of a database tool.
    ///
    /// `db_host`, `db_user`, `database` (and, for `MySQL`, the `tables` that
    /// `mysqldump` reads as positionals) must not start with `-`: the client
    /// would read them as options (`--execute=...`, `--result-file=...`).
    /// `db_password`, `db_host`, `db_user` and `database` must not contain a
    /// newline, carriage return or NUL: they are written to a line-oriented
    /// option or `pgpass` file, where a newline starts a new directive.
    /// A `PostgreSQL` `database` must not be a connection string (see
    /// [`Self::validate_postgres_database`]).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming the offending argument.
    pub fn validate_connection(
        db_type: &DatabaseType,
        db_host: Option<&str>,
        db_user: Option<&str>,
        database: &str,
        db_password: Option<&str>,
        tables: Option<&[String]>,
    ) -> Result<()> {
        for (arg, value) in [
            ("db_host", db_host),
            ("db_user", db_user),
            ("database", Some(database)),
        ] {
            if let Some(v) = value {
                refuse_option_like(arg, v)?;
                refuse_line_break(arg, v)?;
            }
        }
        if let Some(pw) = db_password {
            refuse_line_break("db_password", pw)?;
        }
        if matches!(db_type, DatabaseType::PostgreSQL) {
            Self::validate_postgres_database(database)?;
        }
        if matches!(db_type, DatabaseType::MySQL) {
            for table in tables.unwrap_or_default() {
                refuse_option_like("tables", table)?;
            }
        }
        Ok(())
    }
}

/// Refuse a value holding a newline, carriage return or NUL.
fn refuse_line_break(arg: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0']) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "'{arg}' must not contain a newline, carriage return or NUL: it is written \
                 to a line-oriented credentials file"
            ),
        });
    }
    Ok(())
}

/// Whether the `mysql` client could take `query` for one of its own commands.
///
/// See [`DatabaseCommandBuilder::validate_client_query`] for the rules.
fn mysql_has_client_command(query: &str) -> bool {
    if mysql_client_word_starts_statement(query) {
        return true;
    }
    if !query.contains('\\') {
        return false;
    }
    // The client's string state depends on `sql_mode`, which a `SET` earlier
    // in the same query can change, and on whether a backtick is an escape
    // context: with several statements or backticks next to a backslash the
    // state cannot be known, so the backslash is refused.
    let body = query.trim_end_matches(|c: char| c == ';' || c.is_whitespace());
    if query.contains('`') || body.contains(';') {
        return true;
    }
    mysql_backslash_outside_string(query, true) || mysql_backslash_outside_string(query, false)
}

/// Whether a statement starts with one of [`MYSQL_CLIENT_WORDS`].
///
/// A statement starts at the beginning of the query and after each `;` outside
/// a quoted string and outside a `-- `, `#` or plain `/* */` comment; the
/// whitespace and plain comments before its first word are skipped. The scan
/// runs with and without backslash escapes in strings, as
/// [`mysql_backslash_outside_string`] does.
fn mysql_client_word_starts_statement(query: &str) -> bool {
    let chars: Vec<char> = query.chars().collect();
    statement_starts_with_client_word(&chars, true)
        || statement_starts_with_client_word(&chars, false)
}

/// One pass of [`mysql_client_word_starts_statement`].
fn statement_starts_with_client_word(chars: &[char], backslash_escapes: bool) -> bool {
    let mut i = 0;
    let mut at_statement_start = true;
    while i < chars.len() {
        if at_statement_start {
            i = skip_blanks_and_comments(chars, i);
            let word: String = chars
                .get(i..)
                .unwrap_or_default()
                .iter()
                .copied()
                .take_while(|&c| is_word_char(c))
                .collect::<String>()
                .to_ascii_lowercase();
            if MYSQL_CLIENT_WORDS.contains(&word.as_str()) {
                return true;
            }
            at_statement_start = false;
        }
        let Some(&c) = chars.get(i) else { break };
        let next = chars.get(i + 1).copied();
        let after = chars.get(i + 2).copied();
        match c {
            '\'' | '"' | '`' => i = skip_quoted(chars, i, backslash_escapes),
            ';' => {
                at_statement_start = true;
                i += 1;
            }
            '#' => i = skip_line(chars, i),
            '-' if next == Some('-') && after.is_some_and(|a| a.is_ascii_whitespace()) => {
                i = skip_line(chars, i);
            }
            '/' if next == Some('*') && !matches!(after, Some('!' | '+')) => {
                i = skip_block_comment(chars, i);
            }
            _ => i += 1,
        }
    }
    false
}

/// Index of the first character at or after `from` that is neither
/// whitespace nor part of a plain comment (`-- `, `#`, `/* */`).
fn skip_blanks_and_comments(chars: &[char], from: usize) -> usize {
    let mut i = from;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        let after = chars.get(i + 2).copied();
        if c.is_whitespace() {
            i += 1;
        } else if c == '#'
            || (c == '-' && next == Some('-') && after.is_some_and(|a| a.is_ascii_whitespace()))
        {
            i = skip_line(chars, i);
        } else if c == '/' && next == Some('*') && !matches!(after, Some('!' | '+')) {
            i = skip_block_comment(chars, i);
        } else {
            break;
        }
    }
    i
}

/// Index just past the quoted string (or backtick name) opening at `from`
/// (or the end of the text).
fn skip_quoted(chars: &[char], from: usize, backslash_escapes: bool) -> usize {
    let Some(&quote) = chars.get(from) else {
        return chars.len();
    };
    let mut i = from + 1;
    while let Some(&d) = chars.get(i) {
        i += 1;
        if d == '\\' && backslash_escapes {
            i += 1;
        } else if d == quote {
            return i;
        }
    }
    chars.len()
}

/// Whether `query` has a backslash outside a quoted string and outside a
/// `-- ` or `#` comment.
///
/// `backslash_escapes` says whether a backslash escapes the next character
/// inside quotes (the client's default; off under `NO_BACKSLASH_ESCAPES`).
/// Backticks are scanned like the other quotes, as the client does. `/*!` and
/// `/*+` are text to the client (it runs short-form commands inside them), so
/// they are not skipped; a plain `/* */` comment is. `--` opens a comment
/// only before ASCII whitespace, as the client tests one byte.
fn mysql_backslash_outside_string(query: &str, backslash_escapes: bool) -> bool {
    let chars: Vec<char> = query.chars().collect();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        let after = chars.get(i + 2).copied();
        match c {
            '\'' | '"' | '`' => {
                i += 1;
                while let Some(&d) = chars.get(i) {
                    i += 1;
                    if d == '\\' && backslash_escapes {
                        i += 1;
                    } else if d == c {
                        break;
                    }
                }
            }
            '\\' => return true,
            '#' => i = skip_line(&chars, i),
            '-' if next == Some('-') && after.is_some_and(|a| a.is_ascii_whitespace()) => {
                i = skip_line(&chars, i);
            }
            '/' if next == Some('*') && !matches!(after, Some('!' | '+')) => {
                i = skip_block_comment(&chars, i);
            }
            _ => i += 1,
        }
    }
    false
}

/// Whether `c` can be part of a word of `SQL` text.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Index just past the `*/` closing the block comment that starts at `from`
/// (or the end of the text).
fn skip_block_comment(chars: &[char], from: usize) -> usize {
    chars
        .get(from + 2..)
        .and_then(|rest| rest.windows(2).position(|w| w == ['*', '/']))
        .map_or(chars.len(), |p| from + 2 + p + 2)
}

/// Index of the line break ending the comment that starts at `from`
/// (or the end of the text).
fn skip_line(chars: &[char], from: usize) -> usize {
    chars
        .get(from..)
        .and_then(|rest| rest.iter().position(|&c| c == '\n'))
        .map_or(chars.len(), |p| from + p)
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
            "mysql --defaults-extra-file=$TMPF -h 'localhost' -P 3306 -u 'root' 'mydb' --binary-mode < '/tmp/dump.sql'"
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
        // The client's own commands (`\!`, `system`) stay off for the file.
        assert!(
            cmd.ends_with("'mydb' --binary-mode < '/tmp/dump.sql'"),
            "{cmd}"
        );
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
        assert!(cmd.contains("--binary-mode < '/tmp/dump.sql; cat /etc/shadow'"));
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

    // ── pgpass injection hardening (AUDIT-2026-08 B1) ────────
    //
    // The pgpass line escapes `\` and `:` (the pgpass field format) for host,
    // database and user, but not `'` — and each value is emitted as a
    // single-quoted `printf` argument. Only the password got the POSIX
    // single-quote escape.

    /// Slice out just the `printf ... > $TMPF` pgpass line.
    ///
    /// The same values are also `shell_escape`d elsewhere in the command (for
    /// the `psql` arguments), so asserting on the whole string would pass even
    /// when the pgpass line itself is unescaped.
    fn pgpass_line(cmd: &str) -> &str {
        let start = cmd
            .find(r"printf '%s:%s:%s:%s:%s\n'")
            .expect("pgpass printf must be present");
        let rest = &cmd[start..];
        let end = rest
            .find("> $TMPF")
            .expect("pgpass redirect must be present");
        &rest[..end]
    }

    #[test]
    fn test_pgpass_host_single_quote_cannot_break_out() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "h' ; id ; '",
            5432,
            "postgres",
            Some("pw"),
            "app",
            "SELECT 1",
            None,
        );
        let line = pgpass_line(&cmd);
        assert!(
            !line.contains("'h' ; id ; ''"),
            "db_host must not break out of the printf quoting: {line}"
        );
        assert!(line.contains(r"'h'\'' ; id ; '\'''"), "got: {line}");
    }

    #[test]
    fn test_pgpass_database_single_quote_cannot_break_out() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "postgres",
            Some("pw"),
            "app' ; id ; '",
            "SELECT 1",
            None,
        );
        let line = pgpass_line(&cmd);
        assert!(
            !line.contains("'app' ; id ; ''"),
            "database must not break out of the printf quoting: {line}"
        );
        assert!(line.contains(r"'app'\'' ; id ; '\'''"), "got: {line}");
    }

    #[test]
    fn test_pgpass_user_single_quote_cannot_break_out() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "localhost",
            5432,
            "pg' ; id ; '",
            Some("pw"),
            "app",
            "SELECT 1",
            None,
        );
        let line = pgpass_line(&cmd);
        assert!(
            !line.contains("'pg' ; id ; ''"),
            "db_user must not break out of the printf quoting: {line}"
        );
        assert!(line.contains(r"'pg'\'' ; id ; '\'''"), "got: {line}");
    }

    #[test]
    fn test_pgpass_still_escapes_the_pgpass_field_separator() {
        let cmd = DatabaseCommandBuilder::build_query_command(
            &DatabaseType::PostgreSQL,
            "host:with:colons",
            5432,
            "postgres",
            Some("pw"),
            "app",
            "SELECT 1",
            None,
        );
        assert!(
            pgpass_line(&cmd).contains(r"host\:with\:colons"),
            "pgpass colon escaping must survive: {cmd}"
        );
    }

    // ============== Option injection, client commands, line breaks ==============

    fn denied_naming(result: Result<()>, arg: &str) {
        match result {
            Err(BridgeError::CommandDenied { reason }) => {
                assert!(reason.contains(arg), "reason should name {arg}: {reason}");
            }
            other => panic!("expected CommandDenied naming {arg}, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_connection_refuses_dashed_identifiers() {
        let my = DatabaseType::MySQL;
        denied_naming(
            DatabaseCommandBuilder::validate_connection(&my, None, None, "--execute=x", None, None),
            "database",
        );
        denied_naming(
            DatabaseCommandBuilder::validate_connection(&my, Some("-h"), None, "db", None, None),
            "db_host",
        );
        denied_naming(
            DatabaseCommandBuilder::validate_connection(&my, None, Some("-u"), "db", None, None),
            "db_user",
        );
    }

    #[test]
    fn test_validate_connection_refuses_dashed_mysql_table_only() {
        let tables = ["--result-file=/x".to_string()];
        denied_naming(
            DatabaseCommandBuilder::validate_connection(
                &DatabaseType::MySQL,
                None,
                None,
                "db",
                None,
                Some(tables.as_slice()),
            ),
            "tables",
        );
        // pg_dump reads the table as the value of `-t`.
        assert!(
            DatabaseCommandBuilder::validate_connection(
                &DatabaseType::PostgreSQL,
                None,
                None,
                "db",
                None,
                Some(tables.as_slice()),
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_connection_accepts_ordinary_values() {
        let tables = ["users".to_string(), "orders".to_string()];
        assert!(
            DatabaseCommandBuilder::validate_connection(
                &DatabaseType::MySQL,
                Some("db.example.com"),
                Some("app"),
                "my_db",
                Some("p@ss'w\\ord #1"),
                Some(tables.as_slice()),
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_connection_refuses_line_breaks() {
        let my = DatabaseType::MySQL;
        for pw in ["x\n[client]\ntee=/tmp/o", "x\r!include /tmp/a", "x\0y"] {
            denied_naming(
                DatabaseCommandBuilder::validate_connection(&my, None, None, "db", Some(pw), None),
                "db_password",
            );
        }
        denied_naming(
            DatabaseCommandBuilder::validate_connection(
                &DatabaseType::PostgreSQL,
                None,
                None,
                "db\nhost:5432:*:*:x",
                None,
                None,
            ),
            "database",
        );
    }

    #[test]
    fn test_client_query_refuses_mysql_commands() {
        let my = DatabaseType::MySQL;
        for q in [
            r"\! id > /tmp/o",
            "system id",
            "SYSTEM id",
            "SELECT 1; system id",
            "SELECT 1;\npager cat > /tmp/o",
            "source /etc/passwd",
            "/*! \\! id */",
            "SELECT 1 \\g",
            // Under NO_BACKSLASH_ESCAPES the client closes the string at `\'`.
            r"SELECT '\'; \! id; -- '",
            // The client escapes a backslash inside backticks too: the string
            // stays open at the escaped backtick and `\!` is outside it.
            "SELECT `a\\`` \\! id > /tmp/p",
            // Only ASCII whitespace after `--` makes a comment for the client.
            "SELECT 1 --\u{a0}\\! id > /tmp/p",
            // `SET sql_mode` flips the escape rule partway through the query.
            "SET sql_mode='NO_BACKSLASH_ESCAPES', @x=\"\\\"\"; SELECT '\\'; \\! id > /tmp/p",
            // Client commands that touch files or hosts.
            "ssl_session_data_print /home/app/.ssh/authorized_keys",
            "SSL_SESSION_DATA_PRINT /x",
            "connect db otherhost",
            "CONNECT db otherhost",
            "resetconnection",
            "query_attributes a b",
            // A statement after a `;` (outside strings), blanks or comments.
            "SELECT 1;\r\nSOURCE /etc/passwd",
            "SELECT 1; /* c */ system id",
            "SELECT 1;-- c\nsystem id",
            "/* c */ system id",
            "# c\nsystem id",
            "SELECT 'a'; system id",
            // Under NO_BACKSLASH_ESCAPES the string ends at `\'`.
            "SELECT '\\'; system id; -- '",
        ] {
            denied_naming(
                DatabaseCommandBuilder::validate_client_query(&my, q),
                "query",
            );
        }
    }

    #[test]
    fn test_client_query_accepts_mysql_queries() {
        let my = DatabaseType::MySQL;
        for q in [
            "SELECT 1",
            "SELECT source, system FROM t WHERE tee = 1",
            // A command word at the start of a line is a column, not a command.
            "SELECT id,\n       source,\n       COUNT(*)\nFROM events\nGROUP BY source",
            "SELECT 1\n  system id",
            "SELECT\nedit\nFROM t",
            "SELECT 1 /* c */ system id",
            // A hint, then a column called like a command.
            "SELECT /*+ MAX_EXECUTION_TIME(1000) */ source FROM logs",
            // A `;` inside a string or a comment does not start a statement.
            "SELECT * FROM notes WHERE body = 'done; edit later'",
            "SELECT 1 /* a; system */ FROM t",
            "SELECT 1 -- a; system id\nFROM t",
            "SELECT `a;system` FROM t",
            r"SELECT * FROM t WHERE name LIKE '%\_x' AND b = 'a\\b'",
            r"SELECT 'O\'Brien'",
            "SELECT 1 -- \\! id\n",
            "SELECT 1 /* \\! id */",
            "SELECT a FROM t WHERE b = 'x\\ny'",
            "SELECT 'a\\n';",
            "SELECT 1;\nSELECT 2",
            "SELECT `a;b` FROM t; SELECT `c`",
            "SELECT 1 --\u{a0}not a command",
            "SELECT 1 -- \\! id\nFROM t",
            "SELECT 1 # \\! id",
        ] {
            assert!(
                DatabaseCommandBuilder::validate_client_query(&my, q).is_ok(),
                "{q}"
            );
        }
    }

    #[test]
    fn test_client_query_psql_backslash_command() {
        let pg = DatabaseType::PostgreSQL;
        denied_naming(
            DatabaseCommandBuilder::validate_client_query(&pg, r"\! id"),
            "query",
        );
        denied_naming(
            DatabaseCommandBuilder::validate_client_query(&pg, "  \n\\copy t to '/x'"),
            "query",
        );
        assert!(
            DatabaseCommandBuilder::validate_client_query(&pg, r"SELECT 'a' ~ '\d+', E'\n'")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_query_sees_through_comments() {
        for q in [
            "DROP/**/TABLE users",
            "DELETE/**/FROM t",
            "DROP -- c\n TABLE t",
            "DROP # c\n DATABASE d",
            "DROP SCHEMA prod",
            // MySQL runs the inside of `/*!` and `/*!NNNNN` comments.
            "/*!DROP*/ TABLE users",
            "/*!50000 DROP*/ TABLE t",
            "SELECT 1 /*! 1 */",
            // MariaDB runs the inside of `/*M!NNNNNN` comments.
            "/*M!100100DROP*/ TABLE users",
            "/*M!100100TRUNCATE*/ users",
            "/*M!100100GRANT*/ ALL ON *.* TO x",
            "SELECT 1 /*M! 1 */",
            "DROP TABLES t",
            "DELETE IGNORE FROM t",
            "DELETE LOW_PRIORITY QUICK FROM t",
            // PostgreSQL nests block comments.
            "DROP /* /* */ */ TABLE users",
            "DELETE /*+ x */ FROM t",
        ] {
            assert!(DatabaseCommandBuilder::validate_query(q).is_err(), "{q}");
        }
        assert!(DatabaseCommandBuilder::validate_query("SELECT 1 /* drop */ -- note").is_ok());
        assert!(DatabaseCommandBuilder::validate_query("SELECT 'M!' /* M! */").is_ok());
        assert!(DatabaseCommandBuilder::validate_query("SELECT /* x /* y */ */ 1").is_ok());
        assert!(
            DatabaseCommandBuilder::validate_query("SELECT /*+ MAX_EXECUTION_TIME(1000) */ 1")
                .is_ok()
        );
    }

    #[test]
    fn test_mysql_query_command_disables_client_commands() {
        for password in [None, Some("pw")] {
            let cmd = DatabaseCommandBuilder::build_query_command(
                &DatabaseType::MySQL,
                "localhost",
                3306,
                "root",
                password,
                "db",
                "SELECT 1",
                None,
            );
            assert!(cmd.contains(" --binary-mode -e 'SELECT 1'"), "{cmd}");
        }
    }

    #[test]
    fn test_mysql_restore_command_disables_client_commands() {
        for password in [None, Some("pw")] {
            let cmd = DatabaseCommandBuilder::build_restore_command(
                &DatabaseType::MySQL,
                "localhost",
                3306,
                "root",
                password,
                "db",
                "/tmp/p.sql",
            );
            assert!(cmd.contains(" 'db' --binary-mode < '/tmp/p.sql'"), "{cmd}");
        }
    }

    #[test]
    fn test_validate_postgres_database_refuses_connection_strings() {
        for db in [
            "dbname=postgres host=10.0.0.66 port=5432",
            "a=b",
            "postgres://u@10.0.0.66/db",
            "postgresql://10.0.0.66/db",
            "PostgreSQL://10.0.0.66/db",
            "  postgres://10.0.0.66/db",
        ] {
            denied_naming(
                DatabaseCommandBuilder::validate_postgres_database(db),
                "database",
            );
            denied_naming(
                DatabaseCommandBuilder::validate_connection(
                    &DatabaseType::PostgreSQL,
                    None,
                    None,
                    db,
                    None,
                    None,
                ),
                "database",
            );
        }
        for db in ["postgres", "my_db", "app-prod", "db.v2", "postgres_backup"] {
            assert!(DatabaseCommandBuilder::validate_postgres_database(db).is_ok());
        }
        // The MySQL client does not read the database name as a connection string.
        assert!(
            DatabaseCommandBuilder::validate_connection(
                &DatabaseType::MySQL,
                None,
                None,
                "a=b",
                None,
                None,
            )
            .is_ok()
        );
    }
}
