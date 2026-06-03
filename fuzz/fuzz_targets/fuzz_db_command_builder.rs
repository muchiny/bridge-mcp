#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::database::{DatabaseCommandBuilder, DatabaseType};

fuzz_target!(|data: &str| {
    // Fuzz the database command builder with arbitrary input as queries,
    // database names, user names, passwords, etc.

    // 1. Fuzz query command for MySQL
    let cmd = DatabaseCommandBuilder::build_query_command(
        &DatabaseType::MySQL,
        data, // db_host
        3306,
        data, // db_user
        Some(data), // db_password
        data, // database
        data, // query
        Some("csv"),
    );

    // Invariants:
    // - Must contain the mysql command
    assert!(cmd.contains("mysql"), "MySQL query must contain 'mysql'");
    // - Must contain password env var when password is set
    assert!(cmd.contains("MYSQL_PWD="), "Must set MYSQL_PWD");

    // 2. Fuzz query command for PostgreSQL
    let cmd = DatabaseCommandBuilder::build_query_command(
        &DatabaseType::PostgreSQL,
        data,
        5432,
        data,
        Some(data),
        data,
        data,
        None,
    );
    assert!(cmd.contains("psql"), "PostgreSQL query must contain 'psql'");
    assert!(cmd.contains("PGPASSWORD="), "Must set PGPASSWORD");

    // 3. Fuzz dump command
    let tables = vec![data.to_string()];
    let cmd = DatabaseCommandBuilder::build_dump_command(
        &DatabaseType::MySQL,
        data,
        3306,
        data,
        Some(data),
        data,
        Some(tables.as_slice()),
        Some("gzip"),
        data,
    );
    assert!(cmd.contains("mysqldump"), "Dump must contain 'mysqldump'");
    assert!(cmd.contains("| gzip >"), "Must have gzip compression");

    // 4. Fuzz restore command
    let cmd = DatabaseCommandBuilder::build_restore_command(
        &DatabaseType::PostgreSQL,
        data,
        5432,
        data,
        None,
        data,
        data,
    );
    assert!(cmd.contains("psql"), "Restore must contain 'psql'");
    assert!(!cmd.contains("PGPASSWORD"), "No password env without password");

    // 5. Should never panic (implicit)
});
