#![no_main]

use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::database::{DatabaseCommandBuilder, DatabaseType};

// This target used to assert only the PROGRAM NAME: `assert!(cmd.contains(
// "MYSQL_PWD="))`. That is a string the builder writes itself, in every branch,
// whatever the caller passed — so NO INPUT COULD EVER FAIL IT. A builder that
// pastes `data` into the command line in bare does not panic and does not drop
// the program name; it produces a dangerous command and the target stays
// green. An echo, not a property.
//
// What it asserts now: whatever the builder ACCEPTED arrives in the command as
// TEXT — inside one literal run, having contributed no shell syntax. Refusal
// is always fine; the fuzzer is looking for values that get THROUGH.
//
// `assert_arrives_as_text` rather than `assert_survives_as_one_word`: these
// builders emit pipelines and `&&` chains of their own, and an oracle that
// refuses every operator would be red on healthy code. It is `contains` on the
// literal run rather than equality because a value legitimately lands inside a
// larger word (`--filter=name=VALUE`); an operator still splits the run either
// way, which is what the assertion is for.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_db_command_builder -- -dict=fuzz/dicts/shell.dict`

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
    assert_arrives_as_text(&cmd, data, "MySQL query");
    // - The password must NEVER reach the command line or an env var.
    //   FIND-031 moved these builders to `--defaults-extra-file` (MySQL) and
    //   `PGPASSFILE` (PostgreSQL) precisely so the secret stays out of the
    //   process table. This target used to assert `cmd.contains("MYSQL_PWD=")`
    //   — the pre-fix shape — so it demanded the vulnerability back. It would
    //   have failed on every input, and did not, because the fuzz harness had
    //   not compiled for six weeks.
    assert!(!cmd.contains("MYSQL_PWD"), "password must not travel in MYSQL_PWD: {cmd}");

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
    assert_arrives_as_text(&cmd, data, "PostgreSQL query");
    assert!(!cmd.contains("PGPASSWORD"), "password must not travel in PGPASSWORD: {cmd}");

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
    assert_arrives_as_text(&cmd, data, "Dump");
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
    assert_arrives_as_text(&cmd, data, "Restore");
    assert!(!cmd.contains("PGPASSWORD"), "No password env without password");

    // 5. Should never panic (implicit)
});
